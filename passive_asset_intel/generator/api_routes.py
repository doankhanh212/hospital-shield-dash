"""FastAPI routes for the demo data generator — mounted from main.py."""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request

from passive_asset_intel.generator.generator import DemoDataGenerator
from passive_asset_intel.generator.models import GenerateResult, NetworkConfig
from passive_asset_intel.utils.config import load_config
from passive_asset_intel.utils.logger import setup_logger

router = APIRouter(prefix="/api/generator", tags=["generator"])
logger = setup_logger(__name__)

# PROJECT_ROOT = parent of passive_asset_intel/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.pool


def _timestamp_tag() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


@router.post("/run", response_model=GenerateResult)
async def run_generator(config: NetworkConfig) -> GenerateResult:
    """Generate Zeek TSV logs, then trigger the ingestion + inference pipeline."""
    app_config = load_config()
    zeek_log_dir = Path(app_config.zeek_log_dir)
    output_dir = zeek_log_dir / f"generated_{_timestamp_tag()}"

    logger.info(
        "Generator run requested",
        extra={
            "vlans": len(config.vlans),
            "output_dir": str(output_dir),
        },
    )

    # ── 1. Generate TSV files ────────────────────────────────────────
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        generator = DemoDataGenerator(config, str(output_dir))
        result = generator.generate()
    except Exception as e:
        # Cleanup on failure
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)
        logger.error("Generation failed", extra={"error": str(e)})
        raise HTTPException(
            status_code=500,
            detail={"error": str(e), "stage": "generation"},
        )

    # ── 2. Trigger ingestion + inference pipeline ────────────────────
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "passive_asset_intel",
                "run-all",
                "--log-dir",
                str(output_dir),
            ],
            cwd=str(PROJECT_ROOT),
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        logger.info(
            "Pipeline completed successfully",
            extra={"output_dir": str(output_dir)},
        )
        if proc.stdout:
            logger.info("pipeline stdout", extra={"stdout": proc.stdout[-500:]})
    except subprocess.CalledProcessError as e:
        logger.error(
            "Ingestion pipeline failed",
            extra={
                "returncode": e.returncode,
                "stderr": (e.stderr or "")[-500:],
            },
        )
        # Files are kept — return a partial result with warning
        result.status = "partial"
        result.message = (
            f"Files generated but ingestion failed (exit {e.returncode}): "
            f"{(e.stderr or '').strip()[-200:]}"
        )
        return result
    except subprocess.TimeoutExpired:
        logger.error("Ingestion pipeline timed out")
        result.status = "partial"
        result.message = "Files generated but ingestion timed out after 600s"
        return result
    except Exception as e:
        logger.error("Unexpected pipeline error", extra={"error": str(e)})
        result.status = "partial"
        result.message = f"Files generated but pipeline raised: {e}"
        return result

    return result


@router.get("/status")
async def generator_status(pool: asyncpg.Pool = Depends(_get_pool)) -> dict:
    """Return information about previously generated datasets and current DB state."""
    app_config = load_config()
    zeek_log_dir = Path(app_config.zeek_log_dir)

    generated_dirs: List[str] = []
    last_generated: Optional[str] = None

    if zeek_log_dir.exists():
        dirs = [
            p for p in zeek_log_dir.iterdir()
            if p.is_dir() and p.name.startswith("generated_")
        ]
        dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        generated_dirs = [p.name for p in dirs]
        if dirs:
            last_generated = dt.datetime.fromtimestamp(
                dirs[0].stat().st_mtime
            ).isoformat(timespec="seconds")

    # Total assets in DB
    try:
        async with pool.acquire() as conn:
            total_assets = await conn.fetchval("SELECT COUNT(*) FROM assets")
    except Exception as e:
        logger.error("Failed to query asset count", extra={"error": str(e)})
        total_assets = 0

    return {
        "zeek_log_dir": str(zeek_log_dir).replace("\\", "/"),
        "generated_dirs": generated_dirs,
        "last_generated": last_generated,
        "total_assets_in_db": total_assets,
    }
