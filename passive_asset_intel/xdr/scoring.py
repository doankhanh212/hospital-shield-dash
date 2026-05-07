"""XDR scoring — composes a 0-1 anomaly score from rule weight + baseline
deviation + threat-intel signals.

The score drives severity:

    >= 0.9 → critical
    >= 0.7 → high
    >= 0.4 → medium
    else   → low
"""

from __future__ import annotations

from typing import Any

# Per-rule base weight — represents the intrinsic suspiciousness of the rule
# triggering at all, *before* baselines and intel are factored in.
_BASE_WEIGHT: dict[str, float] = {
    "port_scan":         0.40,
    "dns_spike":         0.30,
    "data_exfiltration": 0.50,
    "rare_ja3":          0.20,
    "rare_domain":       0.20,
    "rogue_device":      0.55,    # unknown asset on managed segment is intrinsically risky
}

# Maximum contribution from each enrichment signal.
_VT_MAX_CONTRIB    = 0.40
_ABUSE_MAX_CONTRIB = 0.30
_DEV_MAX_CONTRIB   = 0.30

# Reference engine count for VT — most modern responses report ~70-90 engines.
_VT_REFERENCE_ENGINES = 90.0


def severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def compute_score(
    anomaly_type: str,
    *,
    deviation: float = 1.0,
    vt_malicious: int = 0,
    vt_suspicious: int = 0,
    abuse_score: int = 0,
) -> float:
    """Return a composite anomaly score in [0.0, 1.0].

    Args:
        anomaly_type:  Rule id (port_scan, dns_spike, data_exfiltration,
                       rare_ja3, rare_domain).
        deviation:     observed_value / baseline_value.  1.0 means "matches
                       baseline exactly"; 3.0 means "3x normal".  For rules
                       where deviation is undefined (rare_ja3, cold start)
                       pass 1.0.
        vt_malicious:  VT engines flagging this IP as malicious.
        vt_suspicious: VT engines flagging this IP as suspicious (weighted half).
        abuse_score:   AbuseIPDB confidence score, 0-100.

    Returns:
        Final score, clamped to [0.0, 1.0].
    """
    base = _BASE_WEIGHT.get(anomaly_type, 0.30)

    # Baseline deviation contribution.  No credit for ≤ 1x; saturates at ~7x.
    dev_excess = max(0.0, float(deviation) - 1.0)
    dev_contrib = min(_DEV_MAX_CONTRIB, dev_excess * 0.05)

    # VT contribution — count malicious fully, suspicious at half weight.
    vt_signal = float(vt_malicious) + 0.5 * float(vt_suspicious)
    vt_contrib = min(_VT_MAX_CONTRIB,
                     (vt_signal / _VT_REFERENCE_ENGINES) * _VT_MAX_CONTRIB)

    # AbuseIPDB contribution — linear in confidence score.
    abuse_contrib = (max(0, min(100, int(abuse_score))) / 100.0) * _ABUSE_MAX_CONTRIB

    score = base + dev_contrib + vt_contrib + abuse_contrib
    return max(0.0, min(1.0, round(score, 3)))


def enrich_alert(alert: dict[str, Any], intel: dict[str, int], deviation: float = 1.0) -> dict[str, Any]:
    """Mutate *alert* in place: attach intel fields, recompute score+severity.

    Returns the same alert dict for chaining.
    """
    alert.setdefault("evidence", {}).update(intel)
    alert["evidence"]["deviation"] = round(float(deviation), 3)

    score = compute_score(
        alert["type"],
        deviation     = deviation,
        vt_malicious  = intel.get("vt_malicious",  0),
        vt_suspicious = intel.get("vt_suspicious", 0),
        abuse_score   = intel.get("abuse_score",   0),
    )
    alert["score"]    = score
    alert["severity"] = severity_from_score(score)
    return alert
