"""Alert service — query and manage alerts stored in PostgreSQL.

Alerts are generated automatically by the ScanService after each scan cycle.
This module provides read/update operations for the REST API layer.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


async def list_alerts(
    conn: asyncpg.Connection,
    *,
    status: str | None = None,
    alert_type: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Fetch alerts with optional filters.

    Returns:
        Dict with ``items`` (list of alert dicts) and ``total`` count.
    """
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if status:
        conditions.append(f"a.status = ${idx}")
        params.append(status)
        idx += 1
    if alert_type:
        conditions.append(f"a.alert_type = ${idx}")
        params.append(alert_type)
        idx += 1
    if severity:
        # Case-insensitive match: frontend sends 'critical', DB stores 'Critical'
        conditions.append(f"LOWER(a.severity) = LOWER(${idx})")
        params.append(severity)
        idx += 1

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Total count
    total = await conn.fetchval(
        f"SELECT COUNT(*) FROM alerts a {where}",
        *params,
    ) or 0

    # Paginated rows
    rows = await conn.fetch(
        f"""
        SELECT
            a.id::text,
            a.alert_type,
            a.severity,
            a.message,
            a.source_ip::text,
            a.asset_id::text AS asset_id,
            a.status,
            a.metadata,
            a.created_at,
            a.updated_at
        FROM alerts a
        {where}
        ORDER BY a.created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    items = []
    for r in rows:
        d = dict(r)
        meta = d.get("metadata")
        if isinstance(meta, str):
            try:
                d["metadata"] = json.loads(meta)
            except (ValueError, TypeError):
                d["metadata"] = {}
        items.append(d)

    return {
        "items": items,
        "total": total,
    }


async def update_alert_status(
    conn: asyncpg.Connection,
    alert_id: str,
    new_status: str,
    note: str | None = None,
) -> dict | None:
    """Update an alert's status and optional note.

    The note is merged into the alert's ``metadata`` jsonb column under the
    key ``note`` so we avoid an extra schema migration.

    Args:
        conn: asyncpg connection.
        alert_id: UUID string of the alert.
        new_status: One of 'new', 'false_positive'.
        note: Optional analyst note describing the rationale.

    Returns:
        Updated alert dict, or None if not found.
    """
    if note is not None:
        row = await conn.fetchrow(
            """
            UPDATE alerts
            SET status = $2,
                updated_at = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('note', $3::text)
            WHERE id = $1::uuid
            RETURNING
                id::text,
                alert_type,
                severity, message,
                source_ip::text,
                asset_id::text AS asset_id,
                status, metadata, created_at, updated_at
            """,
            uuid.UUID(alert_id),
            new_status,
            note,
        )
    else:
        row = await conn.fetchrow(
            """
            UPDATE alerts
            SET status = $2, updated_at = NOW()
            WHERE id = $1::uuid
            RETURNING
                id::text,
                alert_type,
                severity, message,
                source_ip::text,
                asset_id::text AS asset_id,
                status, metadata, created_at, updated_at
            """,
            uuid.UUID(alert_id),
            new_status,
        )
    if not row:
        return None
    d = dict(row)
    meta = d.get("metadata")
    if isinstance(meta, str):
        try:
            d["metadata"] = json.loads(meta)
        except (ValueError, TypeError):
            d["metadata"] = {}
    return d


async def get_alert_counts(conn: asyncpg.Connection) -> dict:
    """Return alert counts grouped by status and severity."""
    rows = await conn.fetch("""
        SELECT status, severity, COUNT(*)::int AS count
        FROM alerts
        GROUP BY status, severity
    """)

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + r["count"]
        sev_key = (r["severity"] or "").lower()
        by_severity[sev_key] = by_severity.get(sev_key, 0) + r["count"]

    # Frontend expects arrays of {status, count} / {severity, count}
    return {
        "total": sum(by_status.values()),
        "by_status": [{"status": k, "count": v} for k, v in by_status.items()],
        "by_severity": [{"severity": k, "count": v} for k, v in by_severity.items()],
    }
