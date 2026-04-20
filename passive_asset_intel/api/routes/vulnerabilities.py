"""Vulnerability endpoints — GET /api/vulnerabilities."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from passive_asset_intel.api.deps import get_conn

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """List vulnerabilities with affected asset counts.

    Returns ``{ items: [...], total: N }`` where each item includes:
    - cve_id, cvss_score, severity, description
    - affected_assets: count of assets linked to this CVE
    """
    try:
        conditions = []
        params: list = []
        idx = 1

        if severity:
            conditions.append(f"v.severity = ${idx}")
            params.append(severity)
            idx += 1

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM vulnerabilities v {where}",
            *params,
        ) or 0

        rows = await conn.fetch(
            f"""
            SELECT
                v.id::text,
                v.cve_id,
                v.cvss_score,
                v.severity,
                v.description,
                COALESCE(ac.cnt, 0)::int AS affected_assets
            FROM vulnerabilities v
            LEFT JOIN (
                SELECT vulnerability_id, COUNT(DISTINCT asset_id)::int AS cnt
                FROM asset_vulnerabilities
                GROUP BY vulnerability_id
            ) ac ON ac.vulnerability_id = v.id
            {where}
            ORDER BY v.cvss_score DESC NULLS LAST
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
            limit,
            offset,
        )

        return {
            "items": [dict(r) for r in rows],
            "total": total,
        }
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability(
    vuln_id: str,
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Get a single vulnerability with the list of affected assets."""
    try:
        row = await conn.fetchrow(
            """
            SELECT
                v.id::text,
                v.cve_id,
                v.cpe,
                v.cvss_score,
                v.severity,
                v.description
            FROM vulnerabilities v
            WHERE v.id = $1::uuid
            """,
            vuln_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        result = dict(row)

        # Fetch affected assets
        assets = await conn.fetch("""
            SELECT
                a.id::text AS asset_id,
                COALESCE(host(ai.ip_address)::text, 'unknown') AS ip,
                a.mac_address,
                a.vendor,
                ir.device_type,
                av.detected_at
            FROM asset_vulnerabilities av
            JOIN assets a ON a.id = av.asset_id
            LEFT JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            LEFT JOIN inference_results ir ON ir.asset_id = a.id
            WHERE av.vulnerability_id = $1::uuid
            ORDER BY av.detected_at DESC
        """, vuln_id)

        result["affected_assets"] = [dict(a) for a in assets]
        return result

    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
