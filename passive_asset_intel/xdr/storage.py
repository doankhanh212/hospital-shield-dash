"""XDR storage layer — async CRUD for xdr_anomalies and xdr_incidents.

Pipeline callers (upsert_*) take an asyncpg.Pool and acquire connections
internally.  API route callers (fetch_*) receive an already-acquired
asyncpg.Connection from the FastAPI dependency injector.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

_DESCRIPTIONS: dict[str, str] = {
    "port_scan":         "Port scan: {unique_ports} unique destination ports contacted",
    "dns_spike":         "DNS spike: {unique_domains} unique domains resolved",
    "data_exfiltration": "Data exfiltration: {bytes_out_mb:.2f} MB sent outbound",
    "rare_ja3":          "Rare JA3 fingerprint(s) observed: {rare_ja3_count} unseen",
    "rare_domain":       "Rare domain(s) resolved: {rare_domain_count} unseen",
    "rogue_device":      "Unknown device on managed segment: MAC {rogue_mac} ({rogue_vendor})",
}


def _description(alert: dict) -> str:
    tmpl = _DESCRIPTIONS.get(alert["type"], alert["type"])
    ev = alert.get("evidence", {})
    try:
        return tmpl.format(**ev)
    except (KeyError, ValueError):
        return tmpl


# ── Pipeline-facing (pool) ────────────────────────────────────────────────────

async def resolve_asset_uuid(conn: asyncpg.Connection, ip: str) -> str | None:
    """Resolve an IP to the legacy MAC-keyed assets.id, or None if unknown.

    Best-effort lookup against asset_ips.  Prefers the primary IP binding,
    falling back to the most recent.  Returns None for IPs the inference
    pipeline has not yet linked to an asset (e.g. external attackers).
    """
    row = await conn.fetchrow(
        """
        SELECT asset_id
        FROM   asset_ips
        WHERE  ip_address = $1::inet
        ORDER BY is_primary DESC, last_seen DESC
        LIMIT  1
        """,
        ip,
    )
    return str(row["asset_id"]) if row else None


async def upsert_anomaly(pool: asyncpg.Pool, alert: dict) -> dict[str, Any]:
    """Upsert an anomaly detected by the Zeek pipeline.

    Expects the alert to already carry ``score`` (0-1) and ``severity`` set
    by the scoring layer.  On conflict (asset_id, type): increments count,
    refreshes evidence/score/severity, and bumps last_seen.

    The legacy ``asset_uuid`` FK is resolved best-effort from asset_ips and
    refreshed on every upsert so newly-classified assets get linked.
    """
    evidence_json = json.dumps(alert.get("evidence", {}))
    score    = float(alert.get("score", 0.0))
    severity = alert.get("severity", "low")
    async with pool.acquire() as conn:
        try:
            asset_uuid = await resolve_asset_uuid(conn, alert["asset"])
        except (asyncpg.PostgresError, ValueError):
            asset_uuid = None  # never block ingestion on FK resolution

        row = await conn.fetchrow(
            """
            INSERT INTO xdr_anomalies
                (asset_id, asset_uuid, type, severity, score, description,
                 evidence, first_seen, last_seen, count)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW(), NOW(), 1)
            ON CONFLICT (asset_id, type) DO UPDATE SET
                asset_uuid  = COALESCE(EXCLUDED.asset_uuid, xdr_anomalies.asset_uuid),
                severity    = EXCLUDED.severity,
                score       = EXCLUDED.score,
                description = EXCLUDED.description,
                evidence    = EXCLUDED.evidence,
                last_seen   = NOW(),
                count       = xdr_anomalies.count + 1
            RETURNING *
            """,
            alert["asset"],
            asset_uuid,
            alert["type"],
            severity,
            score,
            _description(alert),
            evidence_json,
        )
    saved = dict(row)
    logger.info(
        "XDR anomaly upserted",
        extra={"asset_id": saved["asset_id"], "type": saved["type"],
               "score": saved["score"], "severity": saved["severity"],
               "count": saved["count"]},
    )
    return saved


VALID_STATUSES = {"new", "investigating", "escalated", "resolved", "false_positive"}


async def _write_audit(
    conn: asyncpg.Connection,
    *,
    entity_type: str,
    entity_id:   str,
    action:      str,
    old_value:   dict[str, Any] | None,
    new_value:   dict[str, Any] | None,
    actor:       str | None,
) -> None:
    """Insert an audit log row.  Caller is responsible for the surrounding tx."""
    await conn.execute(
        """
        INSERT INTO xdr_audit_log
            (entity_type, entity_id, action, old_value, new_value, actor)
        VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
        """,
        entity_type, entity_id, action,
        json.dumps(old_value) if old_value is not None else None,
        json.dumps(new_value) if new_value is not None else None,
        actor,
    )


async def update_anomaly_status(
    pool: asyncpg.Pool,
    anomaly_id: str,
    status: str,
    actor: str | None,
) -> dict[str, Any] | None:
    """Atomically change an anomaly's status and write an audit row.

    Returns the updated row, or None if the anomaly does not exist.  Raises
    ValueError if *status* is not in VALID_STATUSES.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")

    async with pool.acquire() as conn:
        async with conn.transaction():
            old = await conn.fetchrow(
                "SELECT id, status FROM xdr_anomalies WHERE id = $1 FOR UPDATE",
                anomaly_id,
            )
            if old is None:
                return None
            if old["status"] == status:
                row = await conn.fetchrow(
                    "SELECT * FROM xdr_anomalies WHERE id = $1", anomaly_id,
                )
                return dict(row) if row else None
            row = await conn.fetchrow(
                """
                UPDATE xdr_anomalies
                SET    status     = $2,
                       updated_at = NOW()
                WHERE  id = $1
                RETURNING *
                """,
                anomaly_id, status,
            )
            await _write_audit(
                conn,
                entity_type="anomaly", entity_id=anomaly_id,
                action="status_change",
                old_value={"status": old["status"]},
                new_value={"status": status},
                actor=actor,
            )
    logger.info("XDR anomaly status changed",
                extra={"id": anomaly_id, "from": old["status"], "to": status, "actor": actor})
    return dict(row) if row else None


async def assign_anomaly(
    pool: asyncpg.Pool,
    anomaly_id: str,
    user: str | None,
    actor: str | None,
) -> dict[str, Any] | None:
    """Atomically assign (or unassign with NULL) an anomaly to a user."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            old = await conn.fetchrow(
                "SELECT id, assigned_to FROM xdr_anomalies WHERE id = $1 FOR UPDATE",
                anomaly_id,
            )
            if old is None:
                return None
            row = await conn.fetchrow(
                """
                UPDATE xdr_anomalies
                SET    assigned_to = $2,
                       updated_at  = NOW()
                WHERE  id = $1
                RETURNING *
                """,
                anomaly_id, user,
            )
            await _write_audit(
                conn,
                entity_type="anomaly", entity_id=anomaly_id,
                action="assign",
                old_value={"assigned_to": old["assigned_to"]},
                new_value={"assigned_to": user},
                actor=actor,
            )
    logger.info("XDR anomaly assigned",
                extra={"id": anomaly_id, "user": user, "actor": actor})
    return dict(row) if row else None


async def add_anomaly_note(
    pool: asyncpg.Pool,
    anomaly_id: str,
    note: str,
    actor: str | None,
) -> dict[str, Any] | None:
    """Append a note to an anomaly and write an audit row carrying the note text."""
    note = (note or "").strip()
    if not note:
        raise ValueError("note must not be empty")

    async with pool.acquire() as conn:
        async with conn.transaction():
            old = await conn.fetchrow(
                "SELECT id, note FROM xdr_anomalies WHERE id = $1 FOR UPDATE",
                anomaly_id,
            )
            if old is None:
                return None
            row = await conn.fetchrow(
                """
                UPDATE xdr_anomalies
                SET    note       = $2,
                       updated_at = NOW()
                WHERE  id = $1
                RETURNING *
                """,
                anomaly_id, note,
            )
            await _write_audit(
                conn,
                entity_type="anomaly", entity_id=anomaly_id,
                action="note",
                old_value={"note": old["note"]} if old["note"] else None,
                new_value={"note": note},
                actor=actor,
            )
    logger.info("XDR anomaly note added",
                extra={"id": anomaly_id, "actor": actor, "len": len(note)})
    return dict(row) if row else None


async def fetch_audit_log(
    conn: asyncpg.Connection,
    *,
    entity_type: str | None = None,
    entity_id:   str | None = None,
    asset_id:    str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return audit-log rows, newest first.  When *asset_id* is given,
    pulls every audit row whose entity is an anomaly belonging to that IP."""
    if asset_id:
        rows = await conn.fetch(
            """
            SELECT a.id, a.entity_type, a.entity_id, a.action,
                   a.old_value, a.new_value, a.actor, a.created_at
            FROM   xdr_audit_log a
            JOIN   xdr_anomalies an ON an.id = a.entity_id
            WHERE  a.entity_type = 'anomaly'
              AND  an.asset_id   = $1
            ORDER BY a.created_at DESC
            LIMIT  $2
            """,
            asset_id, limit,
        )
    elif entity_id:
        rows = await conn.fetch(
            """
            SELECT id, entity_type, entity_id, action,
                   old_value, new_value, actor, created_at
            FROM   xdr_audit_log
            WHERE  ($1::text IS NULL OR entity_type = $1)
              AND  entity_id   = $2
            ORDER BY created_at DESC
            LIMIT  $3
            """,
            entity_type, entity_id, limit,
        )
    else:
        rows = await conn.fetch(
            """
            SELECT id, entity_type, entity_id, action,
                   old_value, new_value, actor, created_at
            FROM   xdr_audit_log
            ORDER BY created_at DESC
            LIMIT  $1
            """,
            limit,
        )

    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        for k in ("old_value", "new_value"):
            if isinstance(d[k], str):
                try: d[k] = json.loads(d[k])
                except (json.JSONDecodeError, TypeError): pass
        d["id"]         = str(d["id"])
        d["entity_id"]  = str(d["entity_id"])
        d["created_at"] = str(d["created_at"])
        out.append(d)
    return out


async def upsert_asset(
    pool: asyncpg.Pool,
    ip: str,
    *,
    mac: str | None = None,
    device_type: str | None = None,
) -> None:
    """Register or refresh an XDR asset entry.  Best-effort, non-fatal."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO xdr_assets (ip, mac, device_type, first_seen, last_seen)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (ip) DO UPDATE SET
                mac         = COALESCE(EXCLUDED.mac,         xdr_assets.mac),
                device_type = COALESCE(EXCLUDED.device_type, xdr_assets.device_type),
                last_seen   = NOW()
            """,
            ip, mac, device_type,
        )


async def save_incident(pool: asyncpg.Pool, incident: dict) -> dict[str, Any]:
    """Insert a new XDR incident row.  Returns the saved row."""
    types_json = json.dumps(incident["anomaly_types"])
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO xdr_incidents
                (asset_id, severity, anomaly_types, first_seen, last_seen)
            VALUES ($1, $2, $3::jsonb, NOW(), NOW())
            RETURNING *
            """,
            incident["asset_id"],
            incident["severity"],
            types_json,
        )
    saved = dict(row)
    logger.info(
        "XDR incident created",
        extra={"asset_id": saved["asset_id"], "severity": saved["severity"],
               "anomaly_types": incident["anomaly_types"]},
    )
    return saved


async def upsert_incident(pool: asyncpg.Pool, incident: dict) -> dict[str, Any]:
    """Update the most recent open incident for the asset, or create a new one.

    An incident is considered "open" if its last_seen is within 5 minutes of
    now.  This prevents duplicate incidents from repeated correlation runs
    within the same attack window.

    Resolves the legacy ``asset_uuid`` FK best-effort on every write so the
    linkage is refreshed when an asset is newly classified.
    """
    types_json = json.dumps(incident["anomaly_types"])
    async with pool.acquire() as conn:
        try:
            asset_uuid = await resolve_asset_uuid(conn, incident["asset_id"])
        except (asyncpg.PostgresError, ValueError):
            asset_uuid = None

        async with conn.transaction():
            existing = await conn.fetchrow(
                """
                SELECT id FROM xdr_incidents
                WHERE  asset_id  = $1
                  AND  last_seen > NOW() - INTERVAL '5 minutes'
                ORDER BY last_seen DESC
                LIMIT  1
                FOR UPDATE
                """,
                incident["asset_id"],
            )
            if existing:
                row = await conn.fetchrow(
                    """
                    UPDATE xdr_incidents SET
                        asset_uuid    = COALESCE($4, asset_uuid),
                        severity      = $2,
                        anomaly_types = $3::jsonb,
                        last_seen     = NOW()
                    WHERE id = $1
                    RETURNING *
                    """,
                    existing["id"],
                    incident["severity"],
                    types_json,
                    asset_uuid,
                )
            else:
                row = await conn.fetchrow(
                    """
                    INSERT INTO xdr_incidents
                        (asset_id, asset_uuid, severity, anomaly_types,
                         first_seen, last_seen)
                    VALUES ($1, $2, $3, $4::jsonb, NOW(), NOW())
                    RETURNING *
                    """,
                    incident["asset_id"],
                    asset_uuid,
                    incident["severity"],
                    types_json,
                )
    return dict(row)


# ── API-facing (connection) ───────────────────────────────────────────────────

async def fetch_anomalies(
    conn: asyncpg.Connection,
    *,
    asset_id: str | None = None,
    severity: str | None = None,
    anomaly_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return paginated anomalies enriched with legacy asset metadata.

    Each item carries an ``asset`` block resolved best-effort from the
    existing assets/inference_results tables — NULL fields when the source
    IP is not yet linked to a known asset (e.g. external attackers).
    """
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if asset_id:
        conditions.append(f"a.asset_id = ${idx}")
        params.append(asset_id)
        idx += 1
    if severity:
        conditions.append(f"a.severity = ${idx}")
        params.append(severity)
        idx += 1
    if anomaly_type:
        conditions.append(f"a.type = ${idx}")
        params.append(anomaly_type)
        idx += 1

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    total: int = await conn.fetchval(
        f"SELECT COUNT(*) FROM xdr_anomalies a {where}", *params
    )
    rows = await conn.fetch(
        f"""
        SELECT a.id, a.asset_id, a.asset_uuid, a.type, a.severity,
               a.score, a.description, a.evidence,
               a.first_seen, a.last_seen, a.count,
               a.status, a.assigned_to, a.note, a.updated_at,
               la.mac_address       AS asset_mac,
               la.vendor            AS asset_vendor,
               ir.device_type       AS asset_device_type,
               ir.confidence        AS asset_confidence
        FROM   xdr_anomalies a
        LEFT  JOIN assets la         ON la.id = a.asset_uuid
        LEFT  JOIN LATERAL (
            SELECT device_type, confidence
            FROM   inference_results
            WHERE  asset_id = a.asset_uuid
            ORDER BY created_at DESC
            LIMIT  1
        ) ir ON true
        {where}
        ORDER BY a.last_seen DESC
        LIMIT  ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )
    return {
        "items": [_anomaly_row_to_dict(r) for r in rows],
        "total": total,
    }


async def fetch_incidents(
    conn: asyncpg.Connection,
    *,
    asset_id: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return paginated incidents enriched with legacy asset metadata."""
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if asset_id:
        conditions.append(f"i.asset_id = ${idx}")
        params.append(asset_id)
        idx += 1
    if severity:
        conditions.append(f"i.severity = ${idx}")
        params.append(severity)
        idx += 1

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    total: int = await conn.fetchval(
        f"SELECT COUNT(*) FROM xdr_incidents i {where}", *params
    )
    rows = await conn.fetch(
        f"""
        SELECT i.id, i.asset_id, i.asset_uuid, i.severity, i.anomaly_types,
               i.first_seen, i.last_seen,
               la.mac_address       AS asset_mac,
               la.vendor            AS asset_vendor,
               ir.device_type       AS asset_device_type,
               ir.confidence        AS asset_confidence
        FROM   xdr_incidents i
        LEFT  JOIN assets la         ON la.id = i.asset_uuid
        LEFT  JOIN LATERAL (
            SELECT device_type, confidence
            FROM   inference_results
            WHERE  asset_id = i.asset_uuid
            ORDER BY created_at DESC
            LIMIT  1
        ) ir ON true
        {where}
        ORDER BY i.last_seen DESC
        LIMIT  ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )
    return {
        "items": [_incident_row_to_dict(r) for r in rows],
        "total": total,
    }


# ── Row coercion ─────────────────────────────────────────────────────────────

def _coerce_jsonb_field(d: dict, key: str) -> None:
    if key in d and isinstance(d[key], str):
        try:
            d[key] = json.loads(d[key])
        except (json.JSONDecodeError, TypeError):
            pass


def _stringify_uuid_ts(d: dict) -> None:
    for key in ("id", "asset_uuid", "first_seen", "last_seen", "updated_at"):
        if key in d and d[key] is not None:
            d[key] = str(d[key])


def _extract_asset_block(d: dict) -> dict[str, Any] | None:
    """Pop the joined asset_* columns into a nested ``asset`` dict.

    Returns None when no asset linkage was resolved (asset_uuid IS NULL).
    """
    mac    = d.pop("asset_mac",         None)
    vendor = d.pop("asset_vendor",      None)
    dtype  = d.pop("asset_device_type", None)
    conf   = d.pop("asset_confidence",  None)
    if d.get("asset_uuid") is None and not any((mac, vendor, dtype)):
        return None
    return {
        "uuid":        d.get("asset_uuid"),
        "ip":          d.get("asset_id"),
        "mac":         mac,
        "vendor":      vendor,
        "device_type": dtype,
        "confidence":  float(conf) if conf is not None else None,
    }


def _anomaly_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    _coerce_jsonb_field(d, "evidence")
    _stringify_uuid_ts(d)
    d["asset"] = _extract_asset_block(d)
    return d


def _incident_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    _coerce_jsonb_field(d, "anomaly_types")
    _stringify_uuid_ts(d)
    d["asset"] = _extract_asset_block(d)
    return d


# Back-compat alias — older callers may still import the old name.
def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    _coerce_jsonb_field(d, "evidence")
    _coerce_jsonb_field(d, "anomaly_types")
    _stringify_uuid_ts(d)
    return d
