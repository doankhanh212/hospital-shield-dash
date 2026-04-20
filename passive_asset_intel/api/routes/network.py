"""Network endpoints — GET /api/connections, GET /api/behaviors."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from passive_asset_intel.api.deps import get_conn

router = APIRouter(prefix="/api", tags=["network"])


@router.get("/connections")
async def list_connections(
    limit: int = Query(200, ge=1, le=1000),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """List recent network connections with vendor info."""
    try:
        rows = await conn.fetch(
            """
            SELECT
                c.id::text,
                host(c.src_ip)::text AS src_ip,
                host(c.dst_ip)::text AS dst_ip,
                c.src_port,
                c.dst_port,
                c.protocol,
                c.service,
                c.duration,
                c.bytes_sent,
                c.bytes_received,
                c.timestamp,
                sa.vendor AS src_vendor,
                da.vendor AS dst_vendor
            FROM connections c
            LEFT JOIN assets sa ON sa.id = c.src_asset_id
            LEFT JOIN assets da ON da.id = c.dst_asset_id
            ORDER BY c.timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/behaviors")
async def list_behaviors(
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Aggregated protocol/port behavior patterns."""
    try:
        rows = await conn.fetch(
            """
            SELECT b.protocol, b.port, b.service,
                SUM(b.frequency) AS total_frequency,
                COUNT(DISTINCT b.asset_id) AS asset_count
            FROM behaviors b
            GROUP BY b.protocol, b.port, b.service
            ORDER BY total_frequency DESC
            LIMIT 50
            """
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})
