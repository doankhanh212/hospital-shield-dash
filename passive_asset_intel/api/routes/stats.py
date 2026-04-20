"""Dashboard stats endpoint — GET /api/stats."""

from __future__ import annotations

import asyncio

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from passive_asset_intel.api.deps import get_config, get_pool

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats")
async def get_stats(
    pool: asyncpg.Pool = Depends(get_pool),
    config=Depends(get_config),
):
    """Aggregated KPIs for the dashboard page.

    All asset counts are filtered by LOCAL_SUBNETS so the numbers match
    the assets page.
    """
    try:
        subnets = config.local_subnets_list

        async def _q_one(sql: str, *args) -> dict:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(sql, *args)
                return dict(row) if row else {}

        async def _q_all(sql: str, *args) -> list[dict]:
            async with pool.acquire() as conn:
                rows = await conn.fetch(sql, *args)
                return [dict(r) for r in rows]

        (
            assets,
            conns,
            dns,
            tls,
            http,
            top_protocols,
            top_assets,
            traffic_by_hour,
        ) = await asyncio.gather(
            # Assets — filtered by LOCAL_SUBNETS
            _q_one(
                """
                SELECT
                    COUNT(DISTINCT a.id) AS total,
                    COUNT(DISTINCT a.id) FILTER (
                        WHERE a.last_seen > NOW() - INTERVAL '1 hour'
                    ) AS active,
                    COUNT(DISTINCT a.id) FILTER (
                        WHERE a.mac_address LIKE 'ip:%%'
                    ) AS ip_only,
                    COUNT(DISTINCT a.id) FILTER (
                        WHERE a.mac_address NOT LIKE 'ip:%%'
                    ) AS has_mac
                FROM assets a
                JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
                WHERE ai.ip_address <<= ANY($1::inet[])
                """,
                subnets,
            ),
            _q_one(
                """SELECT COUNT(*) AS total,
                    COUNT(DISTINCT src_asset_id) AS unique_src,
                    COUNT(DISTINCT dst_asset_id) AS unique_dst,
                    COALESCE(SUM(bytes_sent),0) AS total_bytes_sent,
                    COALESCE(SUM(bytes_received),0) AS total_bytes_recv
                    FROM connections""",
            ),
            _q_one(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT asset_id) AS unique_assets FROM dns_queries",
            ),
            _q_one(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT asset_id) AS unique_assets FROM tls_sessions",
            ),
            _q_one(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT asset_id) AS unique_assets FROM http_sessions",
            ),
            _q_all(
                """SELECT protocol, COUNT(*) AS count
                   FROM behaviors GROUP BY protocol ORDER BY count DESC LIMIT 10""",
            ),
            # Top assets — filtered by LOCAL_SUBNETS
            _q_all(
                """
                SELECT
                    a.id::text,
                    a.mac_address,
                    a.vendor,
                    a.confidence_score,
                    host(ai.ip_address)::text AS ip,
                    (SELECT COUNT(*) FROM connections WHERE src_asset_id = a.id) AS conn_count
                FROM assets a
                JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
                WHERE ai.ip_address <<= ANY($1::inet[])
                ORDER BY conn_count DESC
                LIMIT 10
                """,
                subnets,
            ),
            _q_all(
                """SELECT
                    DATE_TRUNC('hour', timestamp) AS hour,
                    COALESCE(SUM(bytes_sent),0)::bigint AS bytes_out,
                    COALESCE(SUM(bytes_received),0)::bigint AS bytes_in,
                    COUNT(*) AS conn_count
                    FROM connections
                    GROUP BY hour ORDER BY hour DESC LIMIT 24""",
            ),
        )

        # traffic_by_hour comes DESC — reverse to chronological order
        traffic_by_hour.reverse()

        return {
            "assets": assets,
            "connections": conns,
            "dns": dns,
            "tls": tls,
            "http": http,
            "topProtocols": top_protocols,
            "topAssets": top_assets,
            "trafficByHour": traffic_by_hour,
        }
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})
