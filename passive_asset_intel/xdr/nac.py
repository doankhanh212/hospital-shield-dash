"""Passive NAC (Network Access Control) decision engine.

Recommends an action — never enforces.  The recommendation rides as
a piece of evidence on the anomaly so the analyst can see what the
platform *would* do in an active-NAC deployment.

Decision matrix:

    rogue_device                     → isolate     critical
    score >= 0.9 (any anomaly)       → isolate     critical
    score >= 0.7                     → restrict    high
    IoT + opens unusual ports        → restrict    high
    score >= 0.4                     → monitor     medium
    else                             → monitor     low
"""

from __future__ import annotations

from typing import Any

# Ports an IoT/Camera device should *not* be initiating outbound.
_IOT_SUSPICIOUS_PORTS = {
    22,    # SSH       — legitimate management is rare from a camera
    23,    # Telnet
    3389,  # RDP
    445,   # SMB
    3306,  # MySQL
    5432,  # Postgres
    6379,  # Redis
}

_IOT_DEVICE_TYPES = {"IoT", "IP Camera", "IoMT", "Printer"}


def _bucket(score: float, action: str) -> tuple[str, str]:
    if action == "isolate":  return action, "critical"
    if action == "restrict": return action, "high"
    if action == "monitor":
        if   score >= 0.4: return action, "medium"
        else:              return action, "low"
    return action, "low"


def decide(
    *,
    anomaly_type:  str,
    score:         float,
    device_type:   str | None = None,
    ports_used:    list[int] | None = None,
) -> dict[str, Any]:
    """Return ``{action, severity_hint, reason}`` for the given anomaly.

    Inputs are read-only; nothing is persisted by this function.
    """
    reasons: list[str] = []
    action  = "monitor"

    if anomaly_type == "rogue_device":
        action = "isolate"
        reasons.append("unknown asset on managed segment")

    if score >= 0.9 and action != "isolate":
        action = "isolate"
        reasons.append(f"composite score {score:.2f} ≥ 0.9")
    elif score >= 0.7 and action == "monitor":
        action = "restrict"
        reasons.append(f"composite score {score:.2f} ≥ 0.7")

    if device_type in _IOT_DEVICE_TYPES and ports_used:
        bad = sorted(set(ports_used) & _IOT_SUSPICIOUS_PORTS)
        if bad and action == "monitor":
            action = "restrict"
            reasons.append(
                f"{device_type} device opens unusual ports {bad}"
            )

    if not reasons:
        reasons.append(f"score {score:.2f} below restrict threshold")

    final_action, severity = _bucket(score, action)
    return {
        "action":         final_action,           # monitor | restrict | isolate
        "severity_hint":  severity,               # low | medium | high | critical
        "reason":         "; ".join(reasons),
        "enforced":       False,                  # passive — never enforce
    }
