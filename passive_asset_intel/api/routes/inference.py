"""Inference endpoints — summaries for dashboard charts."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from passive_asset_intel.api.deps import get_config, get_conn
from passive_asset_intel.auth.deps import require_analyst

router = APIRouter(prefix="/api", tags=["inference"])


@router.get("/inference/summary")
async def inference_summary(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Device type distribution with average confidence scores.

    Filtered by LOCAL_SUBNETS so the pie chart matches the assets page.
    """
    try:
        subnets = config.local_subnets_list
        rows = await conn.fetch(
            """
            SELECT ir.device_type,
                   COUNT(*)::int AS count,
                   ROUND(AVG(ir.confidence)::numeric, 1) AS avg_confidence
            FROM inference_results ir
            JOIN assets a ON a.id = ir.asset_id
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            GROUP BY ir.device_type
            ORDER BY count DESC
            """,
            subnets,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/inference/behavior-summary")
async def behavior_summary(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Behavior type distribution for the dashboard pie chart."""
    try:
        subnets = config.local_subnets_list
        rows = await conn.fetch(
            """
            SELECT COALESCE(ir.behavior_type, 'Unknown') AS behavior_type,
                   COUNT(*)::int AS count
            FROM inference_results ir
            JOIN assets a ON a.id = ir.asset_id
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            GROUP BY ir.behavior_type
            ORDER BY count DESC
            """,
            subnets,
        )
        return [dict(r) for r in rows]
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/inference/confidence-distribution")
async def confidence_distribution(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Confidence score distribution in buckets for histogram.

    Buckets: High (>=90), Medium (60-89), Low (30-59), Very Low (<30).
    """
    try:
        subnets = config.local_subnets_list
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE ir.confidence >= 90)::int AS high,
                COUNT(*) FILTER (WHERE ir.confidence >= 60 AND ir.confidence < 90)::int AS medium,
                COUNT(*) FILTER (WHERE ir.confidence >= 30 AND ir.confidence < 60)::int AS low,
                COUNT(*) FILTER (WHERE ir.confidence < 30)::int AS very_low
            FROM inference_results ir
            JOIN assets a ON a.id = ir.asset_id
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            """,
            subnets,
        )
        return dict(row) if row else {"high": 0, "medium": 0, "low": 0, "very_low": 0}
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.get("/inference/anomaly-summary")
async def anomaly_summary(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Anomaly counts by severity for dashboard cards."""
    try:
        subnets = config.local_subnets_list
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE ia.severity = 'high')::int AS high,
                COUNT(*) FILTER (WHERE ia.severity = 'medium')::int AS medium,
                COUNT(*) FILTER (WHERE ia.severity = 'low')::int AS low,
                COUNT(DISTINCT ir.asset_id)::int AS affected_assets
            FROM inference_anomalies ia
            JOIN inference_results ir ON ir.id = ia.inference_id
            JOIN assets a ON a.id = ir.asset_id
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            """,
            subnets,
        )
        return dict(row) if row else {"total": 0, "high": 0, "medium": 0, "low": 0, "affected_assets": 0}
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})
