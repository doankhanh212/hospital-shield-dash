"""XDR incident builder — constructs incident objects from correlated anomalies.

Also provides ``build_timeline(asset_id)`` which merges per-asset anomalies and
audit-log entries into a chronological event stream for the UI.
"""

from __future__ import annotations

from typing import Any

import asyncpg

from passive_asset_intel.xdr.storage import fetch_audit_log

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
}


def calculate_severity(anomalies: list[dict[str, Any]]) -> str:
    """Return the highest severity across all anomalies.

    Falls back to 'low' when the anomaly list is empty or contains unrecognised
    severity strings.
    """
    best = "low"
    best_rank = 0
    for a in anomalies:
        sev = a.get("severity", "low")
        rank = _SEVERITY_RANK.get(sev, 0)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


def build_incident(asset_id: str, anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a structured incident dict from correlated anomalies.

    Args:
        asset_id:  The originating asset identifier.
        anomalies: Two or more anomaly dicts from xdr_anomalies, all
                   belonging to asset_id and within the correlation window.

    Returns:
        Incident dict ready for ``upsert_incident()``.
    """
    anomaly_types = sorted({a["type"] for a in anomalies})
    severity = calculate_severity(anomalies)
    return {
        "asset_id":      asset_id,
        "severity":      severity,
        "anomaly_types": anomaly_types,
    }


# ── Timeline ─────────────────────────────────────────────────────────────────

async def build_timeline(
    pool: asyncpg.Pool,
    asset_id: str,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return a unified, time-ordered (newest-first) event stream for an asset.

    Merges:
      • anomaly events (one per detection, with type/severity/score)
      • audit-log events (assignments, status changes, notes)

    Output shape::
        { time, type: "anomaly" | "action", description, details: {...} }
    """
    events: list[dict[str, Any]] = []

    async with pool.acquire() as conn:
        # Anomaly events
        rows = await conn.fetch(
            """
            SELECT id, type, severity, score, description,
                   first_seen, last_seen, count, status, assigned_to
            FROM   xdr_anomalies
            WHERE  asset_id = $1
            ORDER BY last_seen DESC
            LIMIT  $2
            """,
            asset_id, limit,
        )
        for r in rows:
            events.append({
                "time":        str(r["last_seen"]),
                "type":        "anomaly",
                "description": r["description"] or r["type"],
                "details": {
                    "anomaly_id": str(r["id"]),
                    "anomaly_type": r["type"],
                    "severity":   r["severity"],
                    "score":      float(r["score"]),
                    "count":      int(r["count"]),
                    "status":     r["status"],
                    "assigned_to": r["assigned_to"],
                },
            })

        # Audit events for the same asset
        audit = await fetch_audit_log(conn, asset_id=asset_id, limit=limit)

    for a in audit:
        old = a.get("old_value") or {}
        new = a.get("new_value") or {}
        actor = a.get("actor") or "system"
        action = a["action"]

        if action == "status_change":
            desc = f"{actor} changed status: {old.get('status', '—')} → {new.get('status', '—')}"
        elif action == "assign":
            old_u, new_u = old.get("assigned_to"), new.get("assigned_to")
            desc = (
                f"{actor} unassigned anomaly" if not new_u
                else f"{actor} assigned anomaly to {new_u}"
                + (f" (was {old_u})" if old_u and old_u != new_u else "")
            )
        elif action == "note":
            text = (new.get("note") or "")[:120]
            desc = f"{actor} added note: \"{text}\""
        elif action == "escalate":
            desc = f"{actor} escalated anomaly"
        else:
            desc = f"{actor} performed {action}"

        events.append({
            "time":        a["created_at"],
            "type":        "action",
            "description": desc,
            "details": {
                "anomaly_id": a["entity_id"],
                "action":     action,
                "actor":      actor,
                "old_value":  old,
                "new_value":  new,
            },
        })

    # Newest-first
    events.sort(key=lambda e: e["time"], reverse=True)
    return events[:limit]
