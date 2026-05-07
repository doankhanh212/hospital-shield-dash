"""XDR response hooks — minimal, future-ready.

Today this only logs.  The interface is intentionally shaped so that a real
response action (containment, NAC quarantine, firewall block, SOAR webhook)
can be plugged in later by adding a strategy implementation behind
``handle_response``.

The Zeek pipeline calls ``handle_response`` after every anomaly upsert.
"""

from __future__ import annotations

from typing import Any

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

# Map severity → action label.  Reads cleanly today; expands tomorrow.
_DEFAULT_ACTIONS: dict[str, str] = {
    "critical": "RESPONSE_TRIGGERED",   # high-confidence threat
    "high":     "ESCALATE_RECOMMENDED",
    "medium":   "MONITOR",
    "low":      "MONITOR",
}


async def handle_response(anomaly: dict[str, Any]) -> dict[str, Any]:
    """Decide and (today: log) the recommended response for an anomaly.

    Args:
        anomaly: The full anomaly row dict as returned by ``upsert_anomaly``.

    Returns:
        A dict ``{"action": str, "reason": str}`` describing what *would*
        happen.  No side effects on the network or hosts.
    """
    severity = (anomaly.get("severity") or "low").lower()
    asset    = anomaly.get("asset_id") or "?"
    atype    = anomaly.get("type")     or "?"
    score    = float(anomaly.get("score") or 0.0)

    action = _DEFAULT_ACTIONS.get(severity, "MONITOR")
    reason = (
        f"severity={severity} score={score:.2f} type={atype}"
        f" asset={asset}"
    )

    if severity == "critical":
        # Future: enqueue containment job, post to SOAR, etc.
        logger.warning(
            "Response triggered (no-op)",
            extra={
                "asset_id": asset,
                "type":     atype,
                "severity": severity,
                "score":    score,
                "action":   action,
            },
        )
    else:
        logger.info(
            "Response evaluated",
            extra={
                "asset_id": asset,
                "type":     atype,
                "severity": severity,
                "action":   action,
            },
        )

    return {"action": action, "reason": reason}
