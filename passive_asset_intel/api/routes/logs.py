"""Log endpoints — GET /api/dns, GET /api/tls, GET /api/http."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from passive_asset_intel.api.deps import get_conn

router = APIRouter(prefix="/api", tags=["logs"])


@router.get("/dns")
async def list_dns(
    limit: int = Query(200, ge=1, le=1000),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """List recent DNS query logs."""
    try:
        rows = await conn.fetch(
            """
            SELECT d.id::text, d.query, d.answer, d.query_type, d.timestamp,
                (SELECT host(ip_address)::text FROM asset_ips
                 WHERE asset_id=d.asset_id
                 ORDER BY is_primary DESC LIMIT 1) AS src_ip
            FROM dns_queries d
            ORDER BY d.timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/tls")
async def list_tls(
    limit: int = Query(200, ge=1, le=1000),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """List recent TLS/SSL session logs."""
    try:
        rows = await conn.fetch(
            """
            SELECT t.id::text, t.server_name, t.version, t.ja3, t.ja3s,
                t.certificate_issuer, t.next_protocol, t.validation_status,
                t.sni_matches_cert, t.ssl_history, t.timestamp,
                (SELECT host(ip_address)::text FROM asset_ips
                 WHERE asset_id=t.asset_id
                 ORDER BY is_primary DESC LIMIT 1) AS src_ip
            FROM tls_sessions t
            ORDER BY t.timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/http")
async def list_http(
    limit: int = Query(200, ge=1, le=1000),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """List recent HTTP session logs."""
    try:
        rows = await conn.fetch(
            """
            SELECT h.id::text, h.host, h.uri, h.method, h.status_code,
                h.user_agent, h.timestamp,
                (SELECT host(ip_address)::text FROM asset_ips
                 WHERE asset_id=h.asset_id
                 ORDER BY is_primary DESC LIMIT 1) AS src_ip
            FROM http_sessions h
            ORDER BY h.timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})
