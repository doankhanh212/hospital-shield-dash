"""Direction-aware device classifier.

Design notes
------------
Zeek gives us one cardinal fact on every flow: who initiated it. That tells
us the *role* of each endpoint (client vs server) at the moment of the
observation. Classification has to honour that role or it will misclassify
— a laptop reaching out to a DICOM modality on TCP/104 is not itself an
IoMT device.

The pipeline is therefore:

1.  **Bucket every signal by direction**
    * CLIENT-only   : JA3, DNS queries, HTTP User-Agent, SNI, HTTP Host,
                      client_dst_ports (ports this asset *reached out to*).
    * SERVER-only   : JA3S, server_listen_ports (ports other hosts reached
                      out to *on this asset*).
    * NEUTRAL       : MAC OUI vendor, DHCP vendor class, hostname. These
                      describe the device itself regardless of role.

2.  **Run rules over each bucket**
    `SERVER_PORT_RULES` fire only against `server_listen_ports`;
    `CLIENT_PORT_RULES` fire only against `client_dst_ports`;
    JA3 rules fire only on client-side fingerprints; JA3S rules only on
    server-side fingerprints. This removes the whole class of
    "server-classified-as-Android" mistakes.

3.  **Correlate across evidence types**
    Per device_type, sum the weights of supporting signals, then:
        * multiply by `(1 + 0.15 × (n_distinct_evidence_types - 1))`
          capped at 1.4 — independent signal types that agree boost
          confidence.
        * penalise by 0.7 when the runner-up's score is ≥ 80% of the
          winner — ambiguity should not look like certainty.

4.  **Normalise to 0–100**
    `confidence = clamp(top_score / MAX_THEORETICAL, 0, 1) × 100`,
    where `MAX_THEORETICAL = 3.0` — the score three strong signals
    (weight ≈ 1.0) could plausibly accumulate. Anything above that is
    capped at 100.

5.  **Unknown handling**
    * No matches → device_type "Unknown", confidence 5.0.
    * Top score < 0.6 (≈ one weak signal) → cap confidence at 30.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

from passive_asset_intel.inference.rules import (
    CLIENT_PORT_RULES,
    DHCP_RULES,
    DNS_RULES,
    HOSTNAME_RULES,
    HTTP_HOST_RULES,
    JA3_CATEGORY_RULES,
    JA3S_CATEGORY_RULES,
    SERVER_PORT_RULES,
    SNI_RULES,
    USER_AGENT_RULES,
    VENDOR_RULES,
)
from passive_asset_intel.inference.anomaly import detect_anomalies
from passive_asset_intel.inference.version_extractor import extract_os_version
from passive_asset_intel.inference.validators import (
    is_real_mac,
    sanitize_hash_set,
    sanitize_port_set,
    sanitize_text_list,
)
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


# Pre-compile every regex pattern in the rule sets once at import time.
# Any rule with an unparseable pattern is reported (once) and its compiled
# form becomes ``None`` so ``_match_regex`` skips it cleanly.
def _compile_regex_rules(rules: list[dict]) -> list[tuple[dict, "re.Pattern[str] | None"]]:
    compiled: list[tuple[dict, re.Pattern[str] | None]] = []
    for rule in rules:
        pattern = rule.get("match_value", "")
        try:
            compiled.append((rule, re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            logger.error(
                "Invalid regex in rule — rule will be skipped",
                extra={"pattern": pattern, "evidence_type": rule.get("evidence_type"), "error": str(exc)},
            )
            compiled.append((rule, None))
    return compiled


_USER_AGENT_COMPILED = _compile_regex_rules(USER_AGENT_RULES)
_DNS_COMPILED = _compile_regex_rules(DNS_RULES)
_SNI_COMPILED = _compile_regex_rules(SNI_RULES)
_HTTP_HOST_COMPILED = _compile_regex_rules(HTTP_HOST_RULES)
_HOSTNAME_COMPILED = _compile_regex_rules(HOSTNAME_RULES)

# ────────────────────────────────────────────────────────────────────────
# Tunables
# ────────────────────────────────────────────────────────────────────────

MAX_THEORETICAL_SCORE: float = 3.5
MULTI_TYPE_BONUS_PER_EXTRA: float = 0.15
MULTI_TYPE_BONUS_CAP: float = 1.40
CONFLICT_RATIO: float = 0.60
CONFLICT_PENALTY: float = 0.70
UNKNOWN_FLOOR_SCORE: float = 0.60
UNKNOWN_FLOOR_CONFIDENCE: float = 30.0
NO_MATCH_CONFIDENCE: float = 5.0

MAC_FALLBACK_CONFIDENCE: float = 25.0

# K-cap: maximum number of evidence matches per (device_type, evidence_type)
# pair.  Prevents score inflation from many rules of the same type firing.
K_CAP: int = 3

# Decay factor: within the top-K matches of the same evidence_type,
# successive matches contribute less:  weight * DECAY^(rank-1).
DECAY_FACTOR: float = 0.7

# Ambiguity threshold: when N or more device_types have positive scores,
# apply 1/log2(N+1) penalty to reflect classification uncertainty.
AMBIGUITY_THRESHOLD: int = 3

# Signal diversity bonus: independent signal *categories* (CLIENT vs SERVER
# vs NEUTRAL) that agree on a device_type get an extra boost.  This rewards
# corroboration from fundamentally different vantage points.
ROLE_DIVERSITY_BONUS: float = 0.10
ROLE_DIVERSITY_CAP: float = 1.30

# Cross-role conflict penalty: if a device_type accumulates votes from both
# CLIENT and SERVER signals, the classification is ambiguous.  We penalise
# unless the device_type is genuinely dual-role (e.g. "Network" devices).
CROSS_ROLE_PENALTY: float = 0.80
DUAL_ROLE_DEVICE_TYPES: frozenset[str] = frozenset({"Network"})

# Signal role constants
ROLE_CLIENT = "CLIENT"
ROLE_SERVER = "SERVER"
ROLE_NEUTRAL = "NEUTRAL"


# ────────────────────────────────────────────────────────────────────────
# Rule runners — one per signal bucket
# ────────────────────────────────────────────────────────────────────────


def _match_exact_port(rules: list[dict], ports: set[int], label_prefix: str, *, signal_role: str) -> list[dict]:
    out: list[dict] = []
    for rule in rules:
        if rule["match_value"] in ports:
            lbl = rule.get("label", str(rule["match_value"]))
            out.append({
                **rule["infer"],
                "weight": rule["weight"],
                "evidence_type": rule["evidence_type"],
                "evidence_value": f"{label_prefix} {rule['match_value']} ({lbl})",
                "signal_role": signal_role,
            })
    return out


def _match_substring(rules: list[dict], values: set[str], ev_label: str, *, signal_role: str) -> list[dict]:
    sorted_values = sorted(values)
    out: list[dict] = []
    for rule in rules:
        needle = rule["match_value"].lower()
        for v in sorted_values:
            if needle in v.lower():
                out.append({
                    **rule["infer"],
                    "weight": rule["weight"],
                    "evidence_type": rule["evidence_type"],
                    "evidence_value": f"{ev_label} contains '{rule['match_value']}' in '{v[:80]}'",
                    "signal_role": signal_role,
                })
                break
    return out


def _match_regex(
    compiled_rules: list[tuple[dict, "re.Pattern[str] | None"]],
    values: list[str] | set[str],
    ev_label: str,
    *,
    signal_role: str,
) -> list[dict]:
    sorted_values = sorted(values) if not isinstance(values, list) else list(values)
    out: list[dict] = []
    for rule, compiled in compiled_rules:
        if compiled is None:
            continue
        for v in sorted_values:
            if not isinstance(v, str):
                continue
            if compiled.search(v):
                out.append({
                    **rule["infer"],
                    "weight": rule["weight"],
                    "evidence_type": rule["evidence_type"],
                    "evidence_value": f"{ev_label} '{v[:80]}' matches /{rule['match_value']}/",
                    "signal_role": signal_role,
                })
                break
    return out


def _match_exact_hash(rules: list[dict], hashes: set[str], ev_label: str, *, signal_role: str) -> list[dict]:
    out: list[dict] = []
    for rule in rules:
        if rule["match_value"] in hashes:
            out.append({
                **rule["infer"],
                "weight": rule["weight"],
                "evidence_type": rule["evidence_type"],
                "evidence_value": f"{ev_label}={rule['match_value']}",
                "signal_role": signal_role,
            })
    return out


def _match_category(rules: list[dict], categories: set[str], ev_label: str, *, signal_role: str) -> list[dict]:
    """Match on pre-categorized values (e.g. ja3_category, ja3s_category).

    Each rule has match_field='ja3_category' or 'ja3s_category' and
    match_value is a category string like 'chrome_tls'.
    """
    out: list[dict] = []
    for rule in rules:
        if rule["match_value"] in categories:
            out.append({
                **rule["infer"],
                "weight": rule["weight"],
                "evidence_type": rule["evidence_type"],
                "evidence_value": f"{ev_label}={rule['match_value']}",
                "signal_role": signal_role,
            })
    return out


# ────────────────────────────────────────────────────────────────────────
# Input normalisation — tolerate the legacy undifferentiated shape
# ────────────────────────────────────────────────────────────────────────


def _normalise_input(asset_data: dict) -> dict:
    """Map whatever the caller passed into the role-aware shape this module
    needs, and strip corrupted / out-of-range signals.

    The engine now fetches role-aware ports directly; older callers still
    pass a single `behaviors` list with `port` = destination port. In that
    case we treat those ports as `client_dst_ports` (that matches how the
    conn_parser writes `behaviors` — from the orig side).
    """
    # Explicit role-aware fields win; sanitise aggressively.
    client_ports = sanitize_port_set(asset_data.get("client_dst_ports"))
    server_ports = sanitize_port_set(asset_data.get("server_listen_ports"))

    # Legacy `behaviors`: port is dst_port from the client's perspective
    # → those are client_dst_ports, not server_listen_ports.
    legacy_ports = [
        beh.get("port") for beh in (asset_data.get("behaviors") or []) if isinstance(beh, dict)
    ]
    client_ports |= sanitize_port_set(legacy_ports)

    # Fingerprints: split ja3 vs ja3s. After the ssl_parser fix they arrive
    # on different asset rows; here we only use whatever belongs to *this*
    # asset row. Hash values are validated (32-hex-char MD5) and
    # lower-cased for deterministic comparison.
    ja3_raw: list[object] = list(asset_data.get("client_ja3") or [])
    ja3s_raw: list[object] = list(asset_data.get("server_ja3s") or [])
    user_agents_raw: list[object] = []
    dhcp_vendors_raw: list[object] = []

    for fp in asset_data.get("fingerprints") or []:
        if not isinstance(fp, dict):
            continue
        if fp.get("ja3"):
            ja3_raw.append(fp["ja3"])
        if fp.get("ja3s"):
            ja3s_raw.append(fp["ja3s"])
        if fp.get("user_agent"):
            user_agents_raw.append(fp["user_agent"])
        if fp.get("dhcp_vendor"):
            dhcp_vendors_raw.append(fp["dhcp_vendor"])

    vendor_raw = asset_data.get("vendor")
    vendor = vendor_raw.strip() if isinstance(vendor_raw, str) else ""

    mac_raw = asset_data.get("mac_address")
    mac = mac_raw if isinstance(mac_raw, str) else None

    return {
        "mac_address": mac,
        "mac_is_real": is_real_mac(mac),
        "vendor": vendor,
        "client_dst_ports": client_ports,
        "server_listen_ports": server_ports,
        "client_ja3": sanitize_hash_set(ja3_raw),
        "server_ja3s": sanitize_hash_set(ja3s_raw),
        "user_agents": set(sanitize_text_list(user_agents_raw)),
        "dhcp_vendors": set(sanitize_text_list(dhcp_vendors_raw)),
        "hostnames": sanitize_text_list(asset_data.get("hostnames")),
        "dns_queries": sanitize_text_list(asset_data.get("dns_queries")),
        "ssl_sni": sanitize_text_list(asset_data.get("ssl_sni")),
        "http_hosts": sanitize_text_list(asset_data.get("http_hosts")),
        # Categorized fields (from categorizer — passed through engine)
        "ja3_categories": asset_data.get("ja3_categories") or set(),
        "ja3s_categories": asset_data.get("ja3s_categories") or set(),
        "has_tls_client": bool(asset_data.get("has_tls_client")),
        "has_tls_server": bool(asset_data.get("has_tls_server")),
        "has_unknown_ja3": bool(asset_data.get("has_unknown_ja3")),
        "has_unknown_ja3s": bool(asset_data.get("has_unknown_ja3s")),
        "behavior_type": asset_data.get("behavior_type", "Unknown"),
    }


# ────────────────────────────────────────────────────────────────────────
# Evidence collection
# ────────────────────────────────────────────────────────────────────────


def _collect_evidence(data: dict) -> list[dict]:
    matches: list[dict] = []

    # ── Direction-aware ports ────────────────────────────────────────
    matches += _match_exact_port(SERVER_PORT_RULES, data["server_listen_ports"], "listens on", signal_role=ROLE_SERVER)
    matches += _match_exact_port(CLIENT_PORT_RULES, data["client_dst_ports"],   "talks to",   signal_role=ROLE_CLIENT)

    # ── Client-only JA3 category signals ────────────────────────────
    matches += _match_category(JA3_CATEGORY_RULES, data["ja3_categories"], "ja3_category", signal_role=ROLE_CLIENT)

    # ── Server-only JA3S category signals ─────────────────────────
    matches += _match_category(JA3S_CATEGORY_RULES, data["ja3s_categories"], "ja3s_category", signal_role=ROLE_SERVER)

    # Fallback: asset served TLS but JA3S category is unknown
    if data["has_tls_server"] and not data["ja3s_categories"]:
        matches.append({
            "device_type": "Server",
            "os": None,
            "os_version": None,
            "vendor": None,
            "weight": 0.40,
            "evidence_type": "ja3s_presence",
            "evidence_value": "served TLS with unknown ja3s category",
            "signal_role": ROLE_SERVER,
        })

    # ── Client-only text signals (compiled patterns) ─────────────────
    matches += _match_regex(_USER_AGENT_COMPILED, data["user_agents"], "user_agent", signal_role=ROLE_CLIENT)
    matches += _match_regex(_DNS_COMPILED,        data["dns_queries"], "dns_query",  signal_role=ROLE_CLIENT)
    matches += _match_regex(_SNI_COMPILED,        data["ssl_sni"],     "ssl_sni",    signal_role=ROLE_CLIENT)
    matches += _match_regex(_HTTP_HOST_COMPILED,  data["http_hosts"],  "http_host",  signal_role=ROLE_CLIENT)

    # ── Neutral (direction-agnostic) signals ─────────────────────────
    if data["vendor"] and data["vendor"] != "Unknown":
        matches += _match_substring(VENDOR_RULES, {data["vendor"]}, "vendor", signal_role=ROLE_NEUTRAL)

    matches += _match_substring(DHCP_RULES,    data["dhcp_vendors"], "dhcp_vendor", signal_role=ROLE_NEUTRAL)
    matches += _match_regex(_HOSTNAME_COMPILED, data["hostnames"],   "hostname",    signal_role=ROLE_NEUTRAL)

    return matches


# ────────────────────────────────────────────────────────────────────────
# Scoring
# ────────────────────────────────────────────────────────────────────────


def _score_device_types(matches: list[dict]) -> dict[str, dict]:
    """For each device_type, aggregate weight with K-cap and decay.

    Scoring model:
    1. Group matches by (device_type, evidence_type).
    2. Per group: keep top K matches, apply decay 0.7^(rank) to each.
    3. Multi-signal-type bonus: more distinct evidence_types → higher multiplier.
    4. Role diversity bonus: signals from different roles boost confidence.
    5. Cross-role conflict penalty for non-dual-role device_types.

    Returns mapping ``device_type → {"score": float, "types": set[str],
    "roles": set[str], "matches": list[dict]}``.
    """
    # Group matches by (device_type, evidence_type) for K-cap with decay
    dt_et_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for m in matches:
        dt = m.get("device_type")
        if not dt:
            continue
        et = m.get("evidence_type", "unknown")
        dt_et_groups[(dt, et)].append(m)

    agg: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"score": 0.0, "types": set(), "roles": set(), "matches": []}
    )

    for (dt, et), group in dt_et_groups.items():
        # Sort by weight descending, keep top K
        sorted_group = sorted(group, key=lambda m: -float(m["weight"]))
        for rank, m in enumerate(sorted_group[:K_CAP]):
            decay = DECAY_FACTOR ** rank  # 1.0, 0.7, 0.49
            effective_weight = float(m["weight"]) * decay
            agg[dt]["score"] += effective_weight
            agg[dt]["types"].add(et)
            agg[dt]["roles"].add(m.get("signal_role", ROLE_NEUTRAL))
            agg[dt]["matches"].append(m)

    for dt, info in agg.items():
        # Multi-signal-type bonus
        n_types = len(info["types"])
        type_bonus = 1.0 + MULTI_TYPE_BONUS_PER_EXTRA * max(0, n_types - 1)
        info["score"] *= min(type_bonus, MULTI_TYPE_BONUS_CAP)

        # Role diversity bonus
        n_roles = len(info["roles"])
        role_bonus = 1.0 + ROLE_DIVERSITY_BONUS * max(0, n_roles - 1)
        info["score"] *= min(role_bonus, ROLE_DIVERSITY_CAP)

        # Cross-role conflict penalty
        has_client = ROLE_CLIENT in info["roles"]
        has_server = ROLE_SERVER in info["roles"]
        if has_client and has_server and dt not in DUAL_ROLE_DEVICE_TYPES:
            info["score"] *= CROSS_ROLE_PENALTY

    return agg


def _choose_os(matches: list[dict], winning_dt: str) -> tuple[str, str | None]:
    """Pick the best OS name + version.

    Prefer OS values from matches that support the winning device_type;
    fall back to the globally highest-weighted OS claim otherwise.
    """
    dt_os: dict[str, float] = defaultdict(float)
    global_os: dict[str, float] = defaultdict(float)
    os_version_by_weight: dict[str, float] = {}

    for m in matches:
        os_name = m.get("os")
        if os_name:
            w = float(m["weight"])
            global_os[os_name] += w
            if m.get("device_type") == winning_dt:
                dt_os[os_name] += w
        osv = m.get("os_version")
        if osv and os_name:
            prev = os_version_by_weight.get(os_name, 0.0)
            if float(m["weight"]) > prev:
                os_version_by_weight[os_name] = float(m["weight"])

    source = dt_os if dt_os else global_os
    if not source:
        return "Unknown", None
    best_os = max(source, key=source.get)

    # Version: pull the highest-weighted os_version paired with this OS.
    best_version: str | None = None
    best_v_weight = 0.0
    for m in matches:
        if m.get("os") == best_os and m.get("os_version"):
            w = float(m["weight"])
            if w > best_v_weight:
                best_version = m["os_version"]
                best_v_weight = w
    return best_os, best_version


def _choose_vendor(
    matches: list[dict],
    winning_dt: str,
    fallback_vendor: str,
) -> str:
    """Pick the highest-weighted vendor claim supporting the winner."""
    best = fallback_vendor or "Unknown"
    best_w = 0.0
    for m in matches:
        v = m.get("vendor")
        if not v:
            continue
        w = float(m["weight"])
        # Prefer vendor claims aligned with the winning device type.
        if m.get("device_type") == winning_dt:
            w *= 1.1
        if w > best_w:
            best = v
            best_w = w
    return best


# ────────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────────


def classify_asset(asset_data: dict) -> dict:
    """Classify a single asset.

    Args:
        asset_data: dict with any of:
            mac_address, vendor,
            client_dst_ports (set[int]),  server_listen_ports (set[int]),
            client_ja3 (set[str]),        server_ja3s (set[str]),
            fingerprints (list[dict]),    behaviors (list[dict]) — legacy,
            hostnames, dns_queries, ssl_sni, http_hosts (list[str]).

    Returns:
        dict with keys: device_type, os, os_version, vendor, cpe,
        confidence (0–100), method, evidence.
    """
    data = _normalise_input(asset_data)
    fallback_vendor = data["vendor"] or "Unknown"

    matches = _collect_evidence(data)

    if not matches:
        # MAC-only fallback: if the OUI resolved to a known vendor whose
        # VENDOR_RULES entry implies a specific device_type, surface that as
        # a low-confidence classification rather than a blind "Unknown". This
        # typically rescues assets seen only as quiet L2 neighbours on the
        # network (DHCP + ARP, no application traffic captured yet).
        if data["mac_is_real"] and data["vendor"]:
            fallback = _mac_vendor_fallback(data["vendor"])
            if fallback is not None:
                logger.info(
                    "MAC-vendor-only fallback classification",
                    extra={
                        "mac": data["mac_address"],
                        "vendor": data["vendor"],
                        "device_type": fallback["device_type"],
                    },
                )
                return {
                    "device_type": fallback["device_type"],
                    "os": "Unknown",
                    "os_version": None,
                    "vendor": fallback["vendor"] or data["vendor"],
                    "cpe": _generate_cpe(
                        fallback["device_type"], "Unknown", None,
                        fallback["vendor"] or data["vendor"],
                    ),
                    "confidence": MAC_FALLBACK_CONFIDENCE,
                    "method": "vendor_oui_fallback",
                    "evidence": [{
                        "evidence_type": "vendor_oui_fallback",
                        "value": f"vendor '{data['vendor']}' implies {fallback['device_type']}",
                        "weight": 0.25,
                    }],
                }

        logger.info(
            "Unknown classification — no rule matched",
            extra={"mac": data["mac_address"], "vendor": fallback_vendor},
        )
        return {
            "device_type": "Unknown",
            "os": "Unknown",
            "os_version": None,
            "vendor": fallback_vendor,
            "cpe": None,
            "confidence": NO_MATCH_CONFIDENCE,
            "method": "none",
            "evidence": [],
        }

    scored = _score_device_types(matches)

    if not scored:
        # Evidence exists but none of it voted for a device_type
        # (e.g. only OS rules fired). Classify as Unknown but surface
        # the evidence so CPE/OS can still be produced downstream.
        os_name, os_version = _choose_os(matches, "Unknown")
        vendor = _choose_vendor(matches, "Unknown", fallback_vendor)
        logger.info(
            "Unknown classification — evidence present but no device_type vote",
            extra={
                "mac": data["mac_address"],
                "vendor": vendor,
                "os": os_name,
                "evidence_types": sorted({m["evidence_type"] for m in matches}),
            },
        )
        return {
            "device_type": "Unknown",
            "os": os_name,
            "os_version": os_version,
            "vendor": vendor,
            "cpe": _generate_cpe("Unknown", os_name, os_version, vendor),
            "confidence": NO_MATCH_CONFIDENCE,
            "method": "+".join(sorted({m["evidence_type"] for m in matches})),
            "evidence": _evidence_list(matches),
        }

    # Ranked device_types. Secondary sort on device_type name makes ties
    # break deterministically instead of depending on dict insertion order.
    ranked = sorted(
        scored.items(),
        key=lambda kv: (-float(kv[1]["score"]), kv[0]),
    )
    winning_dt, winning = ranked[0]
    winning_score = float(winning["score"])

    # Conflict penalty if runner-up is close.
    penalty = 1.0
    runner_dt: str | None = None
    runner_score = 0.0
    if len(ranked) >= 2:
        runner_dt, runner_info = ranked[1]
        runner_score = float(runner_info["score"])
        if winning_score > 0 and runner_score / winning_score >= CONFLICT_RATIO:
            penalty = CONFLICT_PENALTY

    # ── Apply penalties BEFORE normalisation ──────────────────────────
    penalized_score = winning_score * penalty

    # Ambiguity penalty: many competing device_types = lower confidence.
    n_competing = sum(1 for _, info in ranked if float(info["score"]) > 0)
    if n_competing >= AMBIGUITY_THRESHOLD:
        ambiguity_penalty = 1.0 / math.log2(n_competing + 1)
        penalized_score *= ambiguity_penalty

    # Normalise to 0–100.
    raw = penalized_score / MAX_THEORETICAL_SCORE if MAX_THEORETICAL_SCORE > 0 else 0.0
    confidence = max(0.0, min(1.0, raw)) * 100.0

    # ── Ceiling rules based on evidence diversity ─────────────────────
    n_evidence_types = len(winning["types"])
    n_roles = len(winning["roles"])
    if n_evidence_types <= 1:
        confidence = min(confidence, 40.0)
    if n_roles <= 1:
        confidence = min(confidence, 75.0)

    # Unknown-floor: a single weak signal shouldn't read as high confidence.
    if winning_score < UNKNOWN_FLOOR_SCORE:
        confidence = min(confidence, UNKNOWN_FLOOR_CONFIDENCE)

    confidence = round(max(0.0, min(100.0, confidence)), 1)

    os_name, os_version = _choose_os(matches, winning_dt)
    # Mine UA/DHCP for a concrete version. When the rule engine only
    # produced a generic OS like "Windows" but the UA says "Windows NT 10.0",
    # prefer the UA verdict — it's the difference between matching every
    # Windows CVE ever and matching only windows_10.
    ua_os, ua_version = extract_os_version(
        data.get("user_agents") or set(),
        data.get("dhcp_vendors") or set(),
    )
    if ua_os and ua_version:
        if (os_name in (None, "Unknown") or
            (os_name == "Windows" and ua_os.startswith("Windows")) or
            (os_name == "Linux" and ua_os == "Ubuntu Linux")):
            os_name = ua_os
        if not os_version:
            os_version = ua_version
    vendor = _choose_vendor(matches, winning_dt, fallback_vendor)
    cpe = _generate_cpe(winning_dt, os_name, os_version, vendor)

    method = "+".join(sorted({m["evidence_type"] for m in matches}))

    # ── Behavior labeling & anomaly detection (post-scoring) ────────
    behavior_type = data.get("behavior_type", "Unknown")
    anomalies = detect_anomalies(
        device_type=winning_dt,
        behavior_type=behavior_type,
        ja3_categories=data.get("ja3_categories", set()),
        has_unknown_ja3=data.get("has_unknown_ja3", False),
        has_unknown_ja3s=data.get("has_unknown_ja3s", False),
    )

    result = {
        "device_type": winning_dt,
        "os": os_name,
        "os_version": os_version,
        "vendor": vendor,
        "cpe": cpe,
        "confidence": confidence,
        "method": method,
        "evidence": _evidence_list(matches),
        "behavior_type": behavior_type,
        "anomalies": anomalies,
    }

    # Structured logging for operator visibility. We log once per asset.
    log_ctx = {
        "mac": data["mac_address"],
        "device_type": winning_dt,
        "os": os_name,
        "vendor": vendor,
        "confidence": confidence,
        "method": method,
        "winning_score": round(winning_score, 3),
        "runner_up": runner_dt,
        "runner_score": round(runner_score, 3),
    }
    if penalty < 1.0:
        logger.warning("Classification has conflicting signals", extra=log_ctx)
    if confidence < UNKNOWN_FLOOR_CONFIDENCE:
        logger.info("Low-confidence classification", extra=log_ctx)

    return result


def _mac_vendor_fallback(vendor: str) -> dict | None:
    """Return ``{"device_type": str, "vendor": str | None}`` from the first
    VENDOR_RULE whose ``match_value`` is a case-insensitive substring of the
    given vendor string and whose ``infer`` carries a concrete device_type.
    Returns ``None`` if nothing matches.

    This mirrors ``_match_substring`` in spirit but returns a single verdict
    rather than an evidence list — the caller uses it only when no real
    evidence exists, so the first hit is enough.
    """
    v_lower = vendor.lower()
    for rule in VENDOR_RULES:
        needle = rule.get("match_value", "")
        if not isinstance(needle, str) or not needle:
            continue
        if needle.lower() not in v_lower:
            continue
        infer = rule.get("infer") or {}
        dt = infer.get("device_type")
        if dt:
            return {"device_type": dt, "vendor": infer.get("vendor")}
    return None


def _evidence_list(matches: list[dict]) -> list[dict]:
    return [
        {
            "evidence_type": m["evidence_type"],
            "value": m["evidence_value"],
            "weight": float(m["weight"]),
            "signal_role": m.get("signal_role", ROLE_NEUTRAL),
        }
        for m in matches
    ]


# ────────────────────────────────────────────────────────────────────────
# CPE generator — unchanged logic, just kept self-contained.
# ────────────────────────────────────────────────────────────────────────


def _generate_cpe(
    device_type: str,
    os_name: str,
    os_version: str | None,
    vendor: str,
) -> str | None:
    vendor_norm = (vendor or "").lower().replace(" ", "_").replace("-", "_")

    # CPE version segment stays wildcard — NVD stores most vulnerable-CPE
    # entries with ``*`` in the version slot and expresses applicability via
    # ``cpeMatch.versionStart/End``. Embedding a concrete version (e.g. ``10``
    # or ``21h2``) would make virtualMatchString miss most real CVEs, which
    # list ranges rather than point versions. The asset's version is stored
    # separately in ``inference_results.os_version`` and used by nvd_service
    # at *link* time to prune CVEs whose ranges don't cover this asset.

    if "Windows 10" in (os_name or "") or os_version == "10":
        return "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
    if "Windows 11" in (os_name or ""):
        return "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"
    if "Windows 8.1" in (os_name or "") or os_version == "6.3":
        return "cpe:2.3:o:microsoft:windows_8.1:*:*:*:*:*:*:*:*"
    if "Windows 8" in (os_name or "") or os_version == "6.2":
        return "cpe:2.3:o:microsoft:windows_8:*:*:*:*:*:*:*:*"
    if "Windows 7" in (os_name or "") or os_version == "6.1":
        return "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*"
    if "Windows XP" in (os_name or "") or os_version == "5.1":
        return "cpe:2.3:o:microsoft:windows_xp:*:*:*:*:*:*:*:*"
    if os_name == "Windows Server":
        return "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*"
    if os_name == "Windows":
        return "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"

    if os_name == "Ubuntu Linux":
        return "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"
    if os_name in ("Linux", "Linux/curl"):
        return "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"

    if os_name == "Android":
        return "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*"
    if os_name == "macOS":
        return "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"
    if os_name == "VxWorks":
        return "cpe:2.3:o:windriver:vxworks:*:*:*:*:*:*:*:*"
    if os_name == "QNX":
        return "cpe:2.3:o:blackberry:qnx:*:*:*:*:*:*:*:*"

    if device_type == "IoMT" and vendor and vendor != "Unknown":
        return f"cpe:2.3:h:{vendor_norm}:*:*:*:*:*:*:*:*:*"

    if device_type == "Printer":
        if vendor and vendor not in ("Unknown", "HP"):
            return f"cpe:2.3:h:{vendor_norm}:*:*:*:*:*:*:*:*:*"
        if vendor == "HP":
            return "cpe:2.3:h:hp:laserjet:*:*:*:*:*:*:*:*"
        return "cpe:2.3:h:*:printer:*:*:*:*:*:*:*:*"

    if device_type == "IP Camera":
        if vendor and vendor != "Unknown":
            return f"cpe:2.3:h:{vendor_norm}:*:*:*:*:*:*:*:*:*"
        return "cpe:2.3:h:*:ip_camera:*:*:*:*:*:*:*:*"

    return None
