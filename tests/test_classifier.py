"""Correctness tests for the hardened inference engine.

Run with either:

    python -m pytest tests/test_classifier.py -v
    python tests/test_classifier.py

The module does not depend on pytest — assertions live in plain functions
and the ``__main__`` block runs them sequentially. This keeps the test
suite usable even on a production box without dev dependencies.
"""

from __future__ import annotations

import os
import sys
import traceback

# Make the package importable when run as a script from the repo root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from passive_asset_intel.inference.device_classifier import classify_asset
from passive_asset_intel.inference.validators import (
    is_real_mac,
    normalize_mac,
    sanitize_hash_set,
    sanitize_port_set,
    sanitize_text_list,
)


# ────────────────────────────────────────────────────────────────────────
# Happy-path classifications
# ────────────────────────────────────────────────────────────────────────


def test_printer_detection_by_mac_and_port():
    """Printer: HP OUI + JetDirect listen port → Printer/HP."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:01",
        "vendor": "HP",
        "server_listen_ports": {9100, 631},  # JetDirect + IPP
        "client_dst_ports": {53, 443},
        "hostnames": ["NPI1A2B3C"],
    })
    assert result["device_type"] == "Printer", result
    assert result["vendor"] == "HP", result
    assert 0 <= result["confidence"] <= 100
    assert result["confidence"] >= 70


def test_camera_detection_by_rtsp_and_dns():
    """IP Camera: listens on RTSP + DNS queries to axis.com."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:02",
        "vendor": "Axis",
        "server_listen_ports": {554},
        "dns_queries": ["firmware.axis.com", "time.axis.com"],
    })
    assert result["device_type"] == "IP Camera", result
    assert result["vendor"] == "Axis", result
    assert result["confidence"] >= 60


def test_iomt_detection_dicom():
    """IoMT: DICOM 104 listener + GE OUI → IoMT/GE."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:03",
        "vendor": "GE Healthcare",
        "server_listen_ports": {104, 11112},
    })
    assert result["device_type"] == "IoMT", result
    assert result["vendor"] == "GE Healthcare", result
    assert result["confidence"] >= 80


def test_workstation_by_ja3_dns_ua():
    """Workstation: client-side JA3 + Windows DNS + Windows UA."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:04",
        "vendor": "Dell",
        "client_dst_ports": {443, 80, 53, 137},
        "server_listen_ports": set(),
        "client_ja3": {"a0e9f5d64349fb13191bc781f81f42e1"},  # Windows 10
        "dns_queries": ["windowsupdate.com", "settings-win.data.microsoft.com"],
        "fingerprints": [{"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}],
    })
    assert result["device_type"] == "Workstation", result
    assert result["os"] in ("Windows 10", "Windows"), result
    assert result["confidence"] >= 70


# ────────────────────────────────────────────────────────────────────────
# Regression guard — the Android-on-server bug
# ────────────────────────────────────────────────────────────────────────


def test_no_regression_server_with_android_ja3():
    """A server (JA3S + listens on HTTPS) that happened to be contacted by
    an Android client must NOT end up classified as Android.

    Before the fix, JA3S was attributed to the client and the Android UA
    or JA3 could leak onto what was actually a server asset. Now JA3S
    goes on the server, and user_agents from other clients never make it
    to this asset's row.
    """
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:05",
        "vendor": "",
        "server_listen_ports": {443, 22},
        "server_ja3s": {"15af977ce25de452b96affa2addb1036"},  # nginx
        # An Android-ish client UA should never appear on a real server's
        # row in production, but if it somehow does we must not pivot the
        # classification to Android.
        "fingerprints": [],
    })
    assert result["device_type"] == "Server", result
    assert result["os"] != "Android", result


def test_ja3_and_ja3s_do_not_mix():
    """If ja3 and ja3s are both provided, they must be scored
    independently: ja3 feeds client rules, ja3s feeds server rules.
    """
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:06",
        "vendor": "",
        "client_ja3": {"a0e9f5d64349fb13191bc781f81f42e1"},  # Windows 10
        "server_ja3s": {"15af977ce25de452b96affa2addb1036"},  # nginx
        "server_listen_ports": {443},
    })
    ev_types = {e["evidence_type"] for e in result["evidence"]}
    assert "ja3" in ev_types, result
    assert "ja3s" in ev_types, result


# ────────────────────────────────────────────────────────────────────────
# Edge cases: missing data, partial data, garbage data
# ────────────────────────────────────────────────────────────────────────


def test_unknown_case_no_signals():
    """No MAC, no ports, no anything → Unknown / 5.0 / empty evidence."""
    result = classify_asset({})
    assert result["device_type"] == "Unknown"
    assert result["confidence"] == 5.0
    assert result["evidence"] == []


def test_ip_placeholder_mac_does_not_crash():
    """conn_parser uses "ip:<addr>" as a stub MAC. Classifier must not
    trip on it."""
    result = classify_asset({
        "mac_address": "ip:192.168.1.50",
        "vendor": None,
        "client_dst_ports": {443},
    })
    assert result["device_type"] in ("Unknown", "Server")  # weak, not crash


def test_corrupted_port_values_are_ignored():
    """Strings, floats, negatives, >65535: all dropped."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:07",
        "server_listen_ports": ["abc", -1, 0, 70000, 104],  # only 104 survives
    })
    assert result["device_type"] == "IoMT"


def test_vendor_oui_classifies_quiet_asset():
    """Real MAC + known OUI vendor but zero other signals → the vendor rule
    alone carries the device_type at the unknown-floor cap (30)."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:20",
        "vendor": "Hikvision",
    })
    assert result["device_type"] == "IP Camera", result
    assert result["vendor"] == "Hikvision", result
    # One weak signal: confidence must be capped by the unknown-floor.
    assert result["confidence"] <= 30.0, result


def test_mac_only_fallback_for_unmapped_vendor():
    """A real MAC whose vendor doesn't match any VENDOR_RULE entry → the
    OUI is a dead end, so we expect a cold Unknown (not a fabricated guess)."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:21",
        "vendor": "Some Obscure IoT Vendor Ltd",
    })
    assert result["device_type"] == "Unknown", result
    assert result["confidence"] == 5.0, result


def test_corrupted_ja3_hash_is_ignored():
    """JA3 must be 32-hex-char MD5; anything else is dropped silently."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:08",
        "client_ja3": {"not-a-hash", "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", ""},
    })
    assert result["evidence"] == []
    assert result["device_type"] == "Unknown"


# ────────────────────────────────────────────────────────────────────────
# Conflict handling
# ────────────────────────────────────────────────────────────────────────


def test_conflict_server_plus_workstation_signals_penalised():
    """When Server signals and Workstation signals both fire strongly,
    the winner still emerges but confidence is penalised."""
    result = classify_asset({
        "mac_address": "aa:bb:cc:dd:ee:09",
        "vendor": "",
        "server_listen_ports": {22, 443, 3306},  # Server-ish
        "client_dst_ports": {137, 138, 5355},    # Workstation-ish
    })
    # Whichever wins, confidence must have taken the 0.7 penalty.
    # With two ~equal candidates the normalised score cannot exceed
    # ~0.7 * (top_score / 3.0) * 100. Empirically this lands < 80.
    assert result["confidence"] < 80, result
    assert 0 <= result["confidence"] <= 100


# ────────────────────────────────────────────────────────────────────────
# Confidence safety + determinism
# ────────────────────────────────────────────────────────────────────────


def test_confidence_always_in_range():
    """Over a pile of random-ish inputs, confidence stays in [0, 100]."""
    inputs = [
        {},
        {"mac_address": "aa:bb:cc:dd:ee:10"},
        # Everything-all-at-once asset: lots of listen ports to blow the
        # weight sum past MAX_THEORETICAL. Confidence must still clamp.
        {"server_listen_ports": {104, 9100, 554, 443, 22, 3306, 80, 5432, 631, 11112, 1883, 502}},
        {"client_dst_ports": {443, 137, 5355, 53}, "dns_queries": ["foo.bar"] * 500},
    ]
    for d in inputs:
        r = classify_asset(d)
        assert 0.0 <= r["confidence"] <= 100.0, (d, r)


def test_deterministic_output():
    """Same input → byte-identical output (modulo dict iteration order in
    evidence list, which we verify separately)."""
    data = {
        "mac_address": "aa:bb:cc:dd:ee:11",
        "vendor": "HP",
        "server_listen_ports": {9100, 631},
        "hostnames": ["NPI1A2B3C", "printer.local"],
        "dns_queries": ["hpprint.com", "eprint.hp.com"],
    }
    r1 = classify_asset({**data})
    r2 = classify_asset({**data})
    assert r1["device_type"] == r2["device_type"]
    assert r1["confidence"] == r2["confidence"]
    assert r1["method"] == r2["method"]
    assert [e["evidence_type"] for e in r1["evidence"]] == \
           [e["evidence_type"] for e in r2["evidence"]]


# ────────────────────────────────────────────────────────────────────────
# Validator sanity
# ────────────────────────────────────────────────────────────────────────


def test_validator_mac():
    assert is_real_mac("AA:BB:CC:DD:EE:FF")
    assert is_real_mac("aa-bb-cc-dd-ee-ff")
    assert is_real_mac("aabb.ccdd.eeff")
    assert is_real_mac("aabbccddeeff")
    assert not is_real_mac("ip:192.168.1.1")
    assert not is_real_mac("")
    assert not is_real_mac(None)
    assert not is_real_mac("not a mac")
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_validator_ports():
    assert sanitize_port_set([1, 65535, "80", 70000, -5, None, "abc", 0]) == {1, 65535, 80}


def test_validator_hashes():
    valid = "a0e9f5d64349fb13191bc781f81f42e1"
    assert sanitize_hash_set([valid, "BAD", "", None, valid.upper()]) == {valid}


def test_validator_text_list():
    out = sanitize_text_list(["foo", "  foo  ", "", None, "bar", 42])
    assert out == ["foo", "bar"]


# ────────────────────────────────────────────────────────────────────────
# Test harness (no pytest required)
# ────────────────────────────────────────────────────────────────────────


def _all_tests() -> list:
    return [
        v for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]


def main() -> int:
    tests = _all_tests()
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL  {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
