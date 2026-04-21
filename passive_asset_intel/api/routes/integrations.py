"""Integration endpoints — POST /api/integrations/nvd."""

from __future__ import annotations

import asyncio

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from passive_asset_intel.api.deps import get_pool
from passive_asset_intel.api.models import NvdConfigRequest
from passive_asset_intel.services.nvd_service import (
    get_nvd_config,
    save_nvd_config,
    sync_nvd_for_all_cpes,
)

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.post("/nvd")
async def configure_nvd(
    body: NvdConfigRequest,
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Store an NVD API key and trigger a background CVE sync.

    The sync fetches CVEs for all CPEs found in inference_results and
    populates the ``vulnerabilities`` and ``asset_vulnerabilities`` tables.
    """
    if not body.api_key or len(body.api_key) < 10:
        raise HTTPException(status_code=400, detail="Invalid API key")

    try:
        await save_nvd_config(pool, body.api_key)

        # Run NVD sync in background to avoid blocking the request
        background_tasks.add_task(_run_sync, pool)

        return {
            "status": "ok",
            "message": "NVD API key saved. CVE sync started in background.",
        }
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


@router.get("/nvd")
async def get_nvd_status(
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Return the current NVD integration status including last sync time."""
    try:
        config = await get_nvd_config(pool)
        if not config:
            return {
                "configured": False,
                "last_sync_at": None,
            }

        return {
            "configured": bool(config.get("api_key")),
            "last_sync_at": config.get("last_sync_at"),
        }
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


@router.post("/nvd/sync")
async def trigger_nvd_sync(
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Manually trigger a CVE sync from NVD for all known CPEs."""
    try:
        config = await get_nvd_config(pool)
        if not config or not config.get("api_key"):
            raise HTTPException(
                status_code=400,
                detail="NVD API key not configured. Use POST /api/integrations/nvd first.",
            )

        background_tasks.add_task(_run_sync, pool)
        return {"status": "ok", "message": "NVD sync started in background."}
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


@router.post("/nvd/test")
async def test_nvd_sync(
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Synchronously probe NVD for up to 3 CPEs and return a detailed report.

    Purpose: let the analyst verify the integration works *right now* and see
    concrete CVEs matched against their inferred CPEs, without waiting for the
    background full sync to finish.

    Behaviour:
      - Samples the first 3 distinct CPEs from ``inference_results``
      - Uses ``test_mode=True`` — only the most recent 120-day window, cap 30
        CVEs per CPE (full sync goes back to 2022 with a 200 cap)
      - Does NOT update ``last_sync_at`` (full sync remains the source of truth)
      - Upserts any CVE found so the matched CVEs immediately show up in
        Asset Detail
      - Bounded by a 90s timeout so the UI never hangs
    """
    try:
        config = await get_nvd_config(pool)
        if not config or not config.get("api_key"):
            raise HTTPException(
                status_code=400,
                detail="NVD API key not configured. Use POST /api/integrations/nvd first.",
            )

        try:
            result = await asyncio.wait_for(
                sync_nvd_for_all_cpes(pool, max_cpes=3, test_mode=True),
                timeout=90.0,
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail="NVD test timed out after 90s — NVD API may be slow or unreachable.",
            )

        return {"status": "ok", **result}
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("NVD test failed")
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.post("/nvd/generate-alerts")
async def generate_vuln_alerts(
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Synchronously generate vulnerability alerts for all asset-CVE links.

    Inlines the alert-generation logic with proper error propagation (no
    silent exception swallowing) and batched inserts (100 per batch).
    """
    import json as _json
    import uuid as _uuid

    config = await get_nvd_config(pool)
    if not config or not config.get("api_key"):
        raise HTTPException(status_code=400, detail="NVD API key not configured.")

    async with pool.acquire() as conn:
        total_links = await conn.fetchval(
            "SELECT COUNT(*) FROM asset_vulnerabilities"
        ) or 0
        existing_alerts = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE alert_type = 'vulnerability'"
        ) or 0

        # Fetch all asset-vuln pairs that don't yet have an alert
        rows = await conn.fetch("""
            SELECT
                av.asset_id::text       AS asset_id,
                av.vulnerability_id::text AS vulnerability_id,
                v.cve_id,
                v.cvss_score,
                v.description,
                COALESCE(host(ai.ip_address)::text, '') AS ip
            FROM asset_vulnerabilities av
            JOIN vulnerabilities v ON v.id = av.vulnerability_id
            LEFT JOIN asset_ips ai
                ON ai.asset_id = av.asset_id AND ai.is_primary = true
            WHERE NOT EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.alert_type = 'vulnerability'
                  AND a.asset_id::text = av.asset_id::text
                  AND a.metadata->>'vulnerability_id' = av.vulnerability_id::text
            )
        """)

        rows_found = len(rows)
        if not rows:
            return {
                "status": "ok",
                "alerts_created": 0,
                "rows_found": 0,
                "total_asset_vuln_links": total_links,
                "existing_vuln_alerts": existing_alerts,
                "message": "Không có cảnh báo mới (tất cả đã tồn tại hoặc không có dữ liệu CVE).",
            }

        # Build alert tuples
        alert_rows: list[tuple] = []
        for r in rows:
            score = float(r["cvss_score"] or 0)
            if score >= 9.0:
                sev = "Critical"
            elif score >= 7.0:
                sev = "High"
            elif score >= 4.0:
                sev = "Medium"
            else:
                sev = "Low"

            desc = (r["description"] or "").strip().replace("\n", " ")
            if len(desc) > 200:
                desc = desc[:200] + "..."
            cve_id = r["cve_id"] or "CVE-UNKNOWN"
            msg = f"{cve_id} (CVSS {score:.1f}): {desc}" if desc else f"{cve_id} (CVSS {score:.1f})"
            source_ip: str | None = r["ip"] if r["ip"] else None

            alert_rows.append((
                str(_uuid.uuid4()),      # id as text — cast in SQL
                "vulnerability",         # alert_type
                sev,                     # severity
                msg,                     # message
                source_ip,               # source_ip (varchar)
                r["asset_id"],           # asset_id as text — cast in SQL
                _json.dumps({            # metadata (jsonb)
                    "cve_id": cve_id,
                    "vulnerability_id": r["vulnerability_id"],
                    "cvss_score": score,
                }),
            ))

        # Batch insert — 200 rows per batch to stay within asyncpg limits
        BATCH = 200
        total_inserted = 0
        for i in range(0, len(alert_rows), BATCH):
            batch = alert_rows[i: i + BATCH]
            await conn.executemany("""
                INSERT INTO alerts
                    (id, alert_type, severity, message,
                     source_ip, asset_id, metadata,
                     status, created_at, updated_at)
                VALUES (
                    $1::uuid, $2, $3, $4,
                    $5, $6::uuid, $7::jsonb,
                    'new', NOW(), NOW()
                )
                ON CONFLICT DO NOTHING
            """, batch)
            total_inserted += len(batch)

    return {
        "status": "ok",
        "alerts_created": len(alert_rows),
        "rows_found": rows_found,
        "total_asset_vuln_links": total_links,
        "existing_vuln_alerts": existing_alerts,
        "message": f"{len(alert_rows)} cảnh báo mới được tạo từ {rows_found} liên kết CVE.",
    }


async def _run_sync(pool: asyncpg.Pool) -> None:
    """Background task wrapper for NVD sync."""
    try:
        await sync_nvd_for_all_cpes(pool)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Background NVD sync failed")


async def _run_sync(pool: asyncpg.Pool) -> None:
    """Background task wrapper for NVD sync."""
    try:
        await sync_nvd_for_all_cpes(pool)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Background NVD sync failed")
