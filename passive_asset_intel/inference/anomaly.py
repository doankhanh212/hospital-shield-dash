"""Behavior anomaly detection.

Compares the classified device_type against the JA3-derived behavior_type
to flag mismatches that warrant operator investigation.

Anomalies are advisory-only — they NEVER modify device_type, confidence,
or scoring.  They are stored alongside inference results as structured
alerts.
"""

from __future__ import annotations


# ────────────────────────────────────────────────────────────────────────
# Anomaly rule definitions
# ────────────────────────────────────────────────────────────────────────
# Each rule is a dict with:
#   condition(device_type, behavior_type, ctx) → bool
#   severity: "low" | "medium" | "high"
#   message: human-readable explanation template

_ANOMALY_RULES: list[dict] = [
    # ── Server anomalies ──────────────────────────────────────────────
    {
        "id": "SRV_AUTOMATION",
        "condition": lambda dt, bt, ctx: dt == "Server" and bt == "Automation / Script",
        "severity": "medium",
        "message": "Server is using automation/scripting TLS stack ({categories}). "
                   "May indicate a compromised server running outbound scripts.",
    },
    {
        "id": "SRV_UNKNOWN_JA3",
        "condition": lambda dt, bt, ctx: dt == "Server" and ctx.get("has_unknown_ja3"),
        "severity": "low",
        "message": "Server has unrecognised JA3 fingerprint(s). "
                   "TLS stack could not be categorised — review manually.",
    },

    # ── IoT anomalies ─────────────────────────────────────────────────
    {
        "id": "IOT_BROWSING",
        "condition": lambda dt, bt, ctx: dt == "IoT" and bt == "User Browsing",
        "severity": "high",
        "message": "IoT device is using a browser TLS stack ({categories}). "
                   "Possible credential theft or unauthorized browser session.",
    },
    {
        "id": "IOT_AUTOMATION",
        "condition": lambda dt, bt, ctx: dt == "IoT" and bt == "Automation / Script",
        "severity": "medium",
        "message": "IoT device is using scripting TLS stack ({categories}). "
                   "May indicate compromised firmware running outbound scripts.",
    },

    # ── IoMT anomalies ────────────────────────────────────────────────
    {
        "id": "IOMT_BROWSING",
        "condition": lambda dt, bt, ctx: dt == "IoMT" and bt == "User Browsing",
        "severity": "high",
        "message": "Medical device is using a browser TLS stack ({categories}). "
                   "Unauthorized browsing on medical equipment is a compliance risk.",
    },

    # ── Workstation anomalies ─────────────────────────────────────────
    {
        "id": "WS_EMBEDDED",
        "condition": lambda dt, bt, ctx: dt == "Workstation" and bt == "Embedded Device",
        "severity": "medium",
        "message": "Workstation is using an embedded/IoT TLS stack ({categories}). "
                   "Possible misclassification or rogue IoT device.",
    },
    {
        "id": "WS_MEDICAL",
        "condition": lambda dt, bt, ctx: dt == "Workstation" and bt == "Medical Device",
        "severity": "medium",
        "message": "Workstation is using a medical device TLS stack ({categories}). "
                   "Possible misclassification — verify device identity.",
    },
]


def detect_anomalies(
    device_type: str,
    behavior_type: str,
    ja3_categories: set[str],
    *,
    has_unknown_ja3: bool = False,
    has_unknown_ja3s: bool = False,
) -> list[dict]:
    """Evaluate all anomaly rules and return triggered alerts.

    Args:
        device_type: Winning classification (e.g. "Server", "IoT").
        behavior_type: Behavior label from get_behavior_type().
        ja3_categories: Set of JA3 category strings for evidence.
        has_unknown_ja3: True if asset has JA3 hashes not in the map.
        has_unknown_ja3s: True if asset has JA3S hashes not in the map.

    Returns:
        List of anomaly dicts, each with: type, id, severity, message,
        evidence.  Empty list if nothing triggers.
    """
    if behavior_type == "Unknown" and not has_unknown_ja3:
        return []

    ctx = {
        "has_unknown_ja3": has_unknown_ja3,
        "has_unknown_ja3s": has_unknown_ja3s,
    }

    categories_str = ", ".join(sorted(ja3_categories)) if ja3_categories else "unknown"

    anomalies: list[dict] = []
    for rule in _ANOMALY_RULES:
        try:
            if rule["condition"](device_type, behavior_type, ctx):
                anomalies.append({
                    "type": "behavior_anomaly",
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "message": rule["message"].format(categories=categories_str),
                    "evidence": {
                        "device_type": device_type,
                        "behavior_type": behavior_type,
                        "ja3_categories": sorted(ja3_categories),
                    },
                })
        except Exception:
            pass

    return anomalies
