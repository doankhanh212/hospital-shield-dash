"""XDR asset fingerprint engine — passive device-type guessing without
touching the existing inference engine.

This is an *enrichment* layer: it reads what the legacy ingest already
captured (vendor, ports, JA3 count, DNS volume, HTTP user-agent) and
returns a best-guess ``device_type`` + ``confidence`` + ``reasoning``.

Used by:
- the XDR pipeline (after upsert_anomaly) to attach a fingerprint hint
  to the anomaly evidence
- the rogue-device detector (``rogue.py``) to set severity
- API responses for the front-end (when explicit type unknown)

NOTHING here writes back to the legacy ``inference_results`` table — it is
read-only on legacy data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ── Vendor → device-type heuristics ──────────────────────────────────────────
# Lowercased substring → device class.  Order matters: first hit wins.
_VENDOR_HINTS: list[tuple[str, str, int]] = [
    # camera / IoMT
    ("dahua",                    "IP Camera",   80),
    ("hikvision",                "IP Camera",   80),
    ("kbvision",                 "IP Camera",   75),
    ("axis",                     "IP Camera",   75),
    ("uniview",                  "IP Camera",   70),
    # printers / MFP
    ("hewlett packard",          "Printer",     55),  # could be server too
    ("hp inc",                   "Printer",     65),
    ("brother",                  "Printer",     80),
    ("canon",                    "Printer",     75),
    ("epson",                    "Printer",     75),
    # network gear
    ("cisco",                    "Network",     80),
    ("aruba",                    "Network",     80),
    ("tp-link",                  "Network",     65),
    ("hewlett packard enterprise","Network",    70),
    ("ubiquiti",                 "Network",     80),
    ("juniper",                  "Network",     80),
    ("mikrotik",                 "Network",     80),
    ("zte",                      "Network",     65),
    # IoT / smart-home / industrial
    ("xiaomi",                   "IoT",         70),
    ("tuya",                     "IoT",         80),
    ("espressif",                "IoT",         80),
    ("sonoff",                   "IoT",         80),
    ("nest",                     "IoT",         75),
    ("philips",                  "IoT",         55),
    ("amazon technologies",      "IoT",         70),
    ("google",                   "IoT",         55),
    # mobile
    ("apple",                    "Mobile",      55),  # could be Mac too
    ("samsung",                  "Mobile",      65),
    ("huawei device",            "Mobile",      75),
    ("oneplus",                  "Mobile",      80),
    # workstation / server typical OEMs
    ("dell",                     "Workstation", 55),
    ("lenovo",                   "Workstation", 60),
    ("intel corporate",          "Workstation", 50),
    ("microsoft corporation",    "Workstation", 45),
    ("vmware",                   "Server",      65),
    ("supermicro",               "Server",      80),
    # medical (recognized by name fragments — stretch goal)
    ("ge healthcare",            "IoMT",        90),
    ("philips healthcare",       "IoMT",        90),
    ("siemens healthineers",     "IoMT",        90),
    ("medtronic",                "IoMT",        90),
]

_LOCALLY_ADMIN_RE = re.compile(r"^[0-9a-f]{2}", re.I)

# Server-ish service ports that increase Server / Network confidence
_SERVER_PORTS  = {22, 80, 443, 445, 88, 389, 3306, 5432, 6379, 27017, 8080, 8443, 161, 162}
# Common IoT cloud / mqtt / camera ports
_IOT_PORTS     = {1883, 8883, 5683, 8554, 554, 49152}
# Workstation-ish — outbound TLS, DNS-heavy, mDNS
_WS_OUTBOUND   = {53, 5353, 80, 443}


@dataclass
class Fingerprint:
    device_type: str          # IoMT | IoT | Camera | Printer | Network | Server | Workstation | Mobile | Unknown
    confidence:  float        # 0.0 .. 1.0
    reasoning:   list[str]    # human-readable bullets

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_type": self.device_type,
            "confidence":  round(self.confidence, 3),
            "reasoning":   self.reasoning,
        }


def _is_locally_administered(mac: str | None) -> bool:
    if not mac or len(mac) < 2:
        return False
    try:
        first = int(mac[:2], 16)
        return bool(first & 0x02)
    except ValueError:
        return False


def _vendor_match(vendor: str | None) -> tuple[str, int] | None:
    if not vendor:
        return None
    v = vendor.lower()
    for needle, kind, conf in _VENDOR_HINTS:
        if needle in v:
            return (kind, conf)
    return None


def fingerprint(
    *,
    mac: str | None = None,
    vendor: str | None = None,
    ports_used: list[int] | None = None,
    dns_count: int = 0,
    ja3_count: int = 0,
    user_agent: str | None = None,
    hostname: str | None = None,
) -> Fingerprint:
    """Best-effort device classification from passive evidence.

    Args mostly mirror what the legacy parser already extracted.  Missing
    inputs simply lower the confidence — they never raise.
    """
    reasoning: list[str] = []
    candidates: dict[str, int] = {}   # device_type → confidence (0-100)

    def vote(kind: str, weight: int, why: str) -> None:
        candidates[kind] = max(candidates.get(kind, 0), weight)
        reasoning.append(f"{kind}: {why} (+{weight})")

    # 1. Vendor → strong prior
    vm = _vendor_match(vendor)
    if vm:
        vote(vm[0], vm[1], f"vendor='{vendor}'")

    # 2. Locally-administered MAC → almost certainly Mobile
    if _is_locally_administered(mac):
        vote("Mobile", 70, "locally-administered MAC (privacy randomisation)")

    # 3. Port-based hints
    ports = set(ports_used or [])
    server_score  = len(ports & _SERVER_PORTS)
    iot_score     = len(ports & _IOT_PORTS)
    if server_score >= 2:
        vote("Server", 50 + 8 * min(server_score, 5),
             f"opens {server_score} server port(s) ({sorted(ports & _SERVER_PORTS)})")
    if iot_score >= 1:
        vote("IoT", 50 + 10 * iot_score,
             f"speaks IoT/cam protocols ({sorted(ports & _IOT_PORTS)})")

    # 4. JA3 / TLS volume — workstation/mobile signal
    if ja3_count >= 5:
        vote("Workstation", 45 + min(ja3_count, 20),
             f"{ja3_count} distinct JA3 fingerprints (browser-like)")
    elif ja3_count >= 1:
        vote("Workstation", 35,
             f"{ja3_count} JA3 fingerprint(s)")

    # 5. DNS chattiness → workstation / mobile
    if dns_count >= 30:
        vote("Workstation", 40 + min(int(dns_count / 10), 20),
             f"{dns_count} DNS queries (chatty)")

    # 6. User-Agent — if present, often Workstation/Mobile
    if user_agent:
        ua = user_agent.lower()
        if any(k in ua for k in ("android", "iphone", "ipad", "mobile")):
            vote("Mobile", 80, "User-Agent matches mobile")
        elif any(k in ua for k in ("windows nt", "macintosh", "linux x86", "x11;")):
            vote("Workstation", 75, f"User-Agent='{user_agent[:50]}…'")
        elif any(k in ua for k in ("curl", "python", "go-http", "java/")):
            vote("Server", 60, "User-Agent looks like automation/script")

    # 7. Hostname hints
    if hostname:
        h = hostname.lower()
        if any(k in h for k in ("printer", "hp-", "canon-", "brother-", "epson-")):
            vote("Printer",  85, f"hostname='{hostname}'")
        elif any(k in h for k in ("camera", "ipcam", "cam-", "nvr")):
            vote("IP Camera", 85, f"hostname='{hostname}'")
        elif any(k in h for k in ("desktop-", "laptop-", "pc-", "ws-")):
            vote("Workstation", 80, f"hostname='{hostname}'")
        elif any(k in h for k in ("srv", "server", "host-")):
            vote("Server", 80, f"hostname='{hostname}'")

    # ── Aggregate ─────────────────────────────────────────────────────────
    if not candidates:
        return Fingerprint(device_type="Unknown", confidence=0.05,
                           reasoning=["no signals available"])

    best_kind, best_score = max(candidates.items(), key=lambda kv: kv[1])
    # Normalise: bonus when multiple signals agree on same kind
    agreement_bonus = 5 * (len([1 for k in candidates if k == best_kind]) - 1)
    confidence = min(0.99, (best_score + agreement_bonus) / 100.0)

    return Fingerprint(
        device_type=best_kind,
        confidence=confidence,
        reasoning=reasoning,
    )
