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


async def _run_sync(pool: asyncpg.Pool) -> None:
    """Background task wrapper for NVD sync."""
    try:
        await sync_nvd_for_all_cpes(pool)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Background NVD sync failed")
