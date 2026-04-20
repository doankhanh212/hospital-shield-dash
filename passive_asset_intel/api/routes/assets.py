"""Asset endpoints — CRUD: POST, GET, GET/{id}, PUT/{id}, DELETE/{id}."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from passive_asset_intel.api.deps import get_config, get_conn
from passive_asset_intel.api.models import AssetCreate, AssetUpdate
from passive_asset_intel.auth.deps import require_admin, require_analyst

router = APIRouter(prefix="/api", tags=["assets"])

# Valid sort columns — keys are user-facing, values are SQL ORDER BY.
_SORT_MAP: dict[str, str] = {
    "confidence_desc": "COALESCE(ad.confidence, ad.confidence_score, 0) DESC",
    "confidence_asc":  "COALESCE(ad.confidence, ad.confidence_score, 0) ASC",
    "last_seen":       "ad.last_seen DESC",
    "ip":              "ad.ip ASC NULLS LAST",
    "device_type":     "ad.device_type ASC",
}
_DEFAULT_SORT = "confidence_desc"


@router.get("/assets")
async def list_assets(
    limit: int = Query(20, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    sort: str = Query("confidence_desc"),
    device_type: Optional[str] = Query(None),
    behavior_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
    has_anomaly: Optional[bool] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0, le=100),
    max_confidence: Optional[float] = Query(None, ge=0, le=100),
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """List assets — server-side sort, filter, paginate.

    Query params:
      - sort: confidence_desc|confidence_asc|last_seen|ip|device_type
      - device_type: IoMT|IoT|Server|Workstation|Network|Printer|IP Camera|Unknown
      - search: match IP, MAC, vendor, or hostname (case-insensitive substring)
      - status: online|offline
      - vendor: exact match
      - min_confidence / max_confidence: range filter (0–100)
    """
    try:
        subnets = config.local_subnets_list
        order_expr = _SORT_MAP.get(sort, _SORT_MAP[_DEFAULT_SORT])

        # Build dynamic WHERE clauses for the outer query (after CTE dedup)
        outer_wheres: list[str] = []
        params: list = [subnets]  # $1 = subnets
        idx = 2  # next param index

        if device_type:
            outer_wheres.append(f"ad.device_type = ${idx}")
            params.append(device_type)
            idx += 1

        if behavior_type:
            outer_wheres.append(f"COALESCE(ad.behavior_type, 'Unknown') = ${idx}")
            params.append(behavior_type)
            idx += 1

        if search:
            pattern = f"%{search}%"
            outer_wheres.append(
                f"(ad.ip ILIKE ${idx} OR ad.mac ILIKE ${idx} "
                f"OR COALESCE(ad.vendor, '') ILIKE ${idx} "
                f"OR COALESCE(ad.hostname, '') ILIKE ${idx})"
            )
            params.append(pattern)
            idx += 1

        if status:
            if status == "online":
                outer_wheres.append("ad.last_seen > NOW() - INTERVAL '5 minutes'")
            elif status == "offline":
                outer_wheres.append("ad.last_seen <= NOW() - INTERVAL '5 minutes'")

        if vendor:
            outer_wheres.append(f"COALESCE(ad.vendor, '') ILIKE ${idx}")
            params.append(f"%{vendor}%")
            idx += 1

        if min_confidence is not None:
            outer_wheres.append(f"COALESCE(ad.confidence, ad.confidence_score, 0) >= ${idx}")
            params.append(min_confidence)
            idx += 1

        if max_confidence is not None:
            outer_wheres.append(f"COALESCE(ad.confidence, ad.confidence_score, 0) <= ${idx}")
            params.append(max_confidence)
            idx += 1

        if has_anomaly is True:
            outer_wheres.append("ad.anomaly_count > 0")
        elif has_anomaly is False:
            outer_wheres.append("ad.anomaly_count = 0")

        outer_where_sql = (" AND " + " AND ".join(outer_wheres)) if outer_wheres else ""

        # ── Total count (with same filters) ──────────────────
        count_sql = f"""
            WITH asset_data AS (
                SELECT DISTINCT ON (a.id)
                    a.id                                    AS asset_id,
                    CASE WHEN a.mac_address LIKE 'ip:%%'
                         THEN NULL ELSE a.mac_address
                    END                                     AS mac,
                    a.vendor                                AS vendor,
                    a.last_seen                             AS last_seen,
                    a.confidence_score                      AS confidence_score,
                    host(ai.ip_address)::text               AS ip,
                    ah.hostname                             AS hostname,
                    COALESCE(ir.device_type, 'Unknown')     AS device_type,
                    COALESCE(ir.behavior_type, 'Unknown')   AS behavior_type,
                    ir.confidence                           AS confidence,
                    COALESCE((SELECT COUNT(*) FROM inference_anomalies ia
                              WHERE ia.inference_id = ir.id), 0) AS anomaly_count
                FROM assets a
                LEFT JOIN asset_ips         ai ON ai.asset_id = a.id AND ai.is_primary = true
                LEFT JOIN asset_hostnames   ah ON ah.asset_id = a.id
                LEFT JOIN inference_results ir ON ir.asset_id = a.id
                WHERE ai.ip_address <<= ANY($1::inet[])
                ORDER BY a.id
            )
            SELECT COUNT(*) FROM asset_data ad WHERE true{outer_where_sql}
        """
        total = await conn.fetchval(count_sql, *params) or 0

        # ── Paginated rows ───────────────────────────────────
        # Append limit/offset as the last two params
        limit_idx = idx
        offset_idx = idx + 1
        params.append(limit)
        params.append(offset)

        data_sql = f"""
            WITH asset_data AS (
                SELECT DISTINCT ON (a.id)
                    a.id                                                       AS asset_id,
                    CASE
                        WHEN a.mac_address LIKE 'ip:%%' THEN NULL
                        ELSE a.mac_address
                    END                                                        AS mac,
                    a.vendor                                                   AS vendor,
                    a.first_seen                                               AS first_seen,
                    a.last_seen                                                AS last_seen,
                    a.confidence_score                                         AS confidence_score,
                    host(ai.ip_address)::text                                  AS ip,
                    ah.hostname                                                AS hostname,
                    COALESCE(ir.device_type, 'Unknown')                        AS device_type,
                    ir.os                                                      AS os,
                    ir.os_version                                              AS os_version,
                    ir.cpe                                                     AS cpe,
                    ir.confidence                                              AS confidence,
                    ir.method                                                  AS inference_method,
                    COALESCE(ir.behavior_type, 'Unknown')                      AS behavior_type,
                    COALESCE((SELECT COUNT(*) FROM inference_anomalies ia
                              WHERE ia.inference_id = ir.id), 0)               AS anomaly_count,
                    COALESCE((SELECT COUNT(*) FROM inference_anomalies ia
                              WHERE ia.inference_id = ir.id
                                AND ia.severity = 'high'), 0)                  AS anomaly_high,
                    COALESCE((SELECT COUNT(*) FROM asset_vulnerabilities av
                              WHERE av.asset_id = a.id), 0)                    AS vuln_count,
                    COALESCE((SELECT MAX(v.cvss_score)
                              FROM asset_vulnerabilities av
                              JOIN vulnerabilities v ON v.id = av.vulnerability_id
                              WHERE av.asset_id = a.id), 0)                    AS max_cvss,
                    COALESCE((SELECT COUNT(DISTINCT b.port)
                              FROM behaviors b
                              WHERE b.asset_id = a.id
                                AND b.port IS NOT NULL
                                AND b.port > 0), 0)                            AS open_ports
                FROM assets a
                LEFT JOIN asset_ips         ai ON ai.asset_id = a.id AND ai.is_primary = true
                LEFT JOIN asset_hostnames   ah ON ah.asset_id = a.id
                LEFT JOIN inference_results ir ON ir.asset_id = a.id
                WHERE ai.ip_address <<= ANY($1::inet[])
                ORDER BY a.id
            )
            SELECT
                ad.asset_id::text                                              AS id,
                ad.mac,
                ad.mac                                                         AS mac_address,
                ad.vendor,
                ad.first_seen,
                ad.last_seen,
                ad.confidence_score,
                ad.ip,
                ad.hostname,
                ad.device_type,
                ad.device_type                                                 AS "deviceType",
                ad.os,
                ad.os_version,
                ad.os_version                                                  AS "osVersion",
                ad.cpe,
                ad.confidence,
                ad.inference_method,
                ad.inference_method                                            AS method,
                ad.behavior_type,
                ad.anomaly_count::int                                          AS anomaly_count,
                ad.anomaly_high::int                                           AS anomaly_high,
                ad.vuln_count::int                                             AS vuln_count,
                ad.max_cvss::float                                             AS max_cvss,
                ad.open_ports::int                                             AS open_ports,
                (SELECT array_agg(DISTINCT b.protocol)
                 FROM behaviors b WHERE b.asset_id = ad.asset_id)              AS protocols,
                (SELECT array_agg(DISTINCT b.port)
                 FROM behaviors b
                 WHERE b.asset_id = ad.asset_id AND b.port IS NOT NULL)        AS ports,
                (SELECT COUNT(*) FROM connections c
                 WHERE c.src_asset_id = ad.asset_id)                           AS connection_count,
                CASE
                    WHEN ad.last_seen > NOW() - INTERVAL '5 minutes'
                    THEN 'online' ELSE 'offline'
                END                                                            AS status
            FROM asset_data ad
            WHERE true{outer_where_sql}
            ORDER BY {order_expr}, ad.last_seen DESC
            LIMIT ${limit_idx} OFFSET ${offset_idx}
        """

        rows = await conn.fetch(data_sql, *params)
        items = [dict(r) for r in rows]
        return {"items": items, "total": total}

    except asyncpg.PostgresError as e:
        # Degrade gracefully — return empty result so the UI still renders
        # instead of a 500 that breaks the entire assets page.
        import logging
        logging.getLogger(__name__).exception("list_assets database error: %s", e)
        return {"items": [], "total": 0, "error": str(e)}
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("list_assets internal error: %s", e)
        return {"items": [], "total": 0, "error": str(e)}


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_analyst),
):
    """Get full detail for a single asset."""
    try:
        rows = await conn.fetch(
            """
            SELECT
                a.id::text                     AS id,
                CASE
                    WHEN a.mac_address LIKE 'ip:%' THEN NULL
                    ELSE a.mac_address
                END                            AS mac_address,
                a.vendor,
                a.first_seen,
                a.last_seen,
                a.confidence_score,
                (SELECT json_agg(json_build_object(
                    'ip', host(ip_address)::text,
                    'first_seen', ai2.first_seen,
                    'last_seen', ai2.last_seen
                 ))
                 FROM asset_ips ai2 WHERE ai2.asset_id = a.id) AS ips,
                (SELECT json_agg(json_build_object(
                    'hostname', ahn.hostname,
                    'source', ahn.source
                 ))
                 FROM asset_hostnames ahn WHERE ahn.asset_id = a.id) AS hostnames,
                (SELECT json_agg(json_build_object(
                    'protocol', bh.protocol,
                    'port', bh.port,
                    'service', bh.service,
                    'frequency', bh.frequency
                 ) ORDER BY bh.frequency DESC)
                 FROM behaviors bh WHERE bh.asset_id = a.id) AS behaviors,
                (SELECT json_agg(json_build_object(
                    'ja3', fp.ja3,
                    'ja3s', fp.ja3s,
                    'user_agent', fp.user_agent,
                    'dhcp_vendor', fp.dhcp_vendor
                 ))
                 FROM fingerprints fp WHERE fp.asset_id = a.id) AS fingerprints,
                (SELECT json_agg(q.server_name)
                 FROM (
                     SELECT DISTINCT ts.server_name
                     FROM tls_sessions ts
                     WHERE ts.asset_id = a.id
                        AND ts.server_name IS NOT NULL
                     ORDER BY ts.server_name
                     LIMIT 10
                 ) q) AS tls_server_names,
                row_to_json(ir.*) AS inference,
                (SELECT json_agg(json_build_object(
                    'evidence_type', ie.evidence_type,
                    'value', ie.value,
                    'weight', ie.weight
                 ) ORDER BY ie.weight DESC)
                 FROM inference_evidence ie WHERE ie.inference_id = ir.id) AS inference_evidence,
                (SELECT json_agg(json_build_object(
                    'anomaly_id', ia.anomaly_id,
                    'severity', ia.severity,
                    'message', ia.message,
                    'evidence', ia.evidence
                 ) ORDER BY
                    CASE ia.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END)
                 FROM inference_anomalies ia WHERE ia.inference_id = ir.id) AS anomalies,
                (SELECT json_agg(json_build_object(
                    'cve_id', v.cve_id,
                    'cvss_score', v.cvss_score,
                    'severity', v.severity,
                    'description', v.description,
                    'detected_at', av.detected_at
                 ) ORDER BY v.cvss_score DESC NULLS LAST)
                 FROM asset_vulnerabilities av
                 JOIN vulnerabilities v ON v.id = av.vulnerability_id
                 WHERE av.asset_id = a.id) AS vulnerabilities
            FROM assets a
            LEFT JOIN inference_results ir ON ir.asset_id = a.id
            WHERE a.id = $1::uuid
            """,
            asset_id,
        )
        if not rows:
            raise HTTPException(status_code=404, detail={"error": "Not found"})

        row = dict(rows[0])
        for key in (
            "ips", "hostnames", "behaviors", "fingerprints",
            "tls_server_names", "inference", "inference_evidence",
            "anomalies", "vulnerabilities",
        ):
            val = row.get(key)
            if isinstance(val, str):
                row[key] = json.loads(val)
        return row
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


# ─── POST /api/assets ────────────────────────────────────────────────────────

@router.post("/assets", status_code=201)
async def create_asset(
    body: AssetCreate,
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_admin),
):
    """Create a new asset manually."""
    now = datetime.now(timezone.utc)
    asset_id = uuid.uuid4()

    try:
        existing = await conn.fetchval(
            "SELECT id FROM assets WHERE mac_address = $1", body.mac_address,
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Asset with MAC {body.mac_address} already exists (id: {existing})",
            )

        async with conn.transaction():
            await conn.execute("""
                INSERT INTO assets (id, mac_address, vendor, first_seen, last_seen,
                                    asset_status, confidence_score)
                VALUES ($1, $2, $3, $4, $4, 'active', 0.5)
            """, asset_id, body.mac_address, body.vendor, now)

            if body.ip_address:
                await conn.execute("""
                    INSERT INTO asset_ips (id, asset_id, ip_address, first_seen, last_seen, is_primary)
                    VALUES ($1, $2, $3::inet, $4, $4, true)
                """, uuid.uuid4(), asset_id, body.ip_address, now)

            if body.hostname:
                await conn.execute("""
                    INSERT INTO asset_hostnames (id, asset_id, hostname, source, first_seen, last_seen)
                    VALUES ($1, $2, $3, 'manual', $4, $4)
                """, uuid.uuid4(), asset_id, body.hostname, now)

        return {
            "id": str(asset_id),
            "mac_address": body.mac_address,
            "ip_address": body.ip_address,
            "vendor": body.vendor,
            "hostname": body.hostname,
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
        }
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


# ─── PUT /api/assets/{id} ────────────────────────────────────────────────────

@router.put("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_admin),
):
    """Update an existing asset's fields."""
    now = datetime.now(timezone.utc)

    try:
        existing = await conn.fetchrow(
            "SELECT id, mac_address FROM assets WHERE id = $1::uuid", asset_id,
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Asset not found")

        async with conn.transaction():
            updates = ["last_seen = $2"]
            params: list = [uuid.UUID(asset_id), now]
            pidx = 3

            if body.mac_address is not None:
                dup = await conn.fetchval(
                    "SELECT id FROM assets WHERE mac_address = $1 AND id != $2::uuid",
                    body.mac_address, asset_id,
                )
                if dup:
                    raise HTTPException(
                        status_code=409,
                        detail=f"MAC {body.mac_address} already used by asset {dup}",
                    )
                updates.append(f"mac_address = ${pidx}")
                params.append(body.mac_address)
                pidx += 1

            if body.vendor is not None:
                updates.append(f"vendor = ${pidx}")
                params.append(body.vendor)
                pidx += 1

            set_clause = ", ".join(updates)
            await conn.execute(
                f"UPDATE assets SET {set_clause} WHERE id = $1::uuid", *params,
            )

            if body.ip_address is not None:
                await conn.execute("""
                    INSERT INTO asset_ips (id, asset_id, ip_address, first_seen, last_seen, is_primary)
                    VALUES ($1, $2::uuid, $3::inet, $4, $4, true)
                    ON CONFLICT (asset_id, ip_address)
                        DO UPDATE SET last_seen = GREATEST(asset_ips.last_seen, EXCLUDED.last_seen)
                """, uuid.uuid4(), uuid.UUID(asset_id), body.ip_address, now)

            if body.hostname is not None:
                await conn.execute("""
                    INSERT INTO asset_hostnames (id, asset_id, hostname, source, first_seen, last_seen)
                    VALUES ($1, $2::uuid, $3, 'manual', $4, $4)
                    ON CONFLICT (asset_id, hostname)
                        DO UPDATE SET last_seen = GREATEST(asset_hostnames.last_seen, EXCLUDED.last_seen)
                """, uuid.uuid4(), uuid.UUID(asset_id), body.hostname, now)

        return {"id": asset_id, "status": "updated"}
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


# ─── DELETE /api/assets/{id} ─────────────────────────────────────────────────

@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: str,
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_admin),
):
    """Delete an asset and all associated records."""
    try:
        existing = await conn.fetchval(
            "SELECT id FROM assets WHERE id = $1::uuid", asset_id,
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Asset not found")

        aid = uuid.UUID(asset_id)

        async with conn.transaction():
            await conn.execute("""
                DELETE FROM inference_evidence
                WHERE inference_id IN (SELECT id FROM inference_results WHERE asset_id = $1)
            """, aid)

            for table in (
                "inference_results", "asset_vulnerabilities", "asset_tags",
                "fingerprints", "behaviors", "dns_queries",
                "http_sessions", "tls_sessions", "asset_ips", "asset_hostnames",
            ):
                await conn.execute(f"DELETE FROM {table} WHERE asset_id = $1", aid)

            await conn.execute(
                "DELETE FROM connections WHERE src_asset_id = $1 OR dst_asset_id = $1", aid,
            )
            await conn.execute("DELETE FROM assets WHERE id = $1", aid)

        return {"id": asset_id, "status": "deleted"}
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
