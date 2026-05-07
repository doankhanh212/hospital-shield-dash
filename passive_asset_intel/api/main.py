"""FastAPI application entry point.

Run with::

    uvicorn passive_asset_intel.api.main:app --port 3001 --reload
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from passive_asset_intel.api.routes import (
    alerts,
    assets,
    inference,
    integrations,
    logs,
    network,
    reports,
    scan,
    stats,
    topology,
    vulnerabilities,
)
from passive_asset_intel.api.routes import auth as auth_routes
from passive_asset_intel.api.routes import data as data_routes
from passive_asset_intel.api.routes import soc as soc_routes
from passive_asset_intel.api.routes import xdr as xdr_routes
from passive_asset_intel.db.schema_fixes import ensure_alert_indexes
from passive_asset_intel.xdr.schema import backfill_asset_uuid_links, ensure_xdr_schema
from passive_asset_intel.generator.api_routes import router as generator_router
from passive_asset_intel.services.disk_manager import DiskManager
from passive_asset_intel.services.scan_service import ScanService
from passive_asset_intel.utils.config import load_config
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the asyncpg pool lifecycle — create on startup, close on shutdown."""
    config = load_config()
    logger.info(
        "Creating asyncpg pool",
        extra={"host": config.db_host, "port": config.db_port, "db": config.db_name},
    )
    pool = await asyncpg.create_pool(
        host=config.db_host,
        port=config.db_port,
        database=config.db_name,
        user=config.db_user,
        password=config.db_password,
        min_size=config.db_pool_min,
        max_size=config.db_pool_max,
        statement_cache_size=0,
    )
    await ensure_alert_indexes(pool)
    await ensure_xdr_schema(pool)
    await backfill_asset_uuid_links(pool)
    app.state.pool = pool
    app.state.config = config
    app.state.scan_service = ScanService(pool, config)

    # Start background disk-manager (log-file + DB record retention)
    disk_manager = DiskManager(pool, config)
    app.state.disk_manager = disk_manager
    disk_manager.start()

    logger.info("API server ready")
    yield
    # Gracefully stop any running scan before shutdown
    if app.state.scan_service:
        await app.state.scan_service.stop()
    # Stop disk manager
    if hasattr(app.state, "disk_manager"):
        await app.state.disk_manager.stop()
    await pool.close()
    logger.info("asyncpg pool closed")


app = FastAPI(
    title="HQG Security Platform API",
    version="2.1.0",
    lifespan=lifespan,
)

config = load_config()

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api_cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all routers — they already carry the /api prefix
app.include_router(auth_routes.router)   # /api/auth/* — login / me (public)
app.include_router(assets.router)
app.include_router(stats.router)
app.include_router(network.router)
app.include_router(logs.router)
app.include_router(inference.router)
app.include_router(topology.router)
app.include_router(scan.router)
app.include_router(alerts.router)
app.include_router(vulnerabilities.router)
app.include_router(integrations.router)
app.include_router(reports.router)
app.include_router(generator_router)
app.include_router(xdr_routes.router)
app.include_router(soc_routes.router)
app.include_router(data_routes.router)


_HEALTH_DB_TIMEOUT_S = 3.0


@app.get("/health")
async def health():
    """Health probe — never blocks, always returns partial data on failure.

    Shape:
        status:    "ok" | "degraded"
        database:  { connected, latency_ms, error? }
        zeek:      { running, pid? }
        ingestion: { status, events_per_sec, last_log_timestamp, ... }
        assets:    { total, classified, unknown }

    Every DB query is wrapped in ``asyncio.wait_for`` with a 3-second budget
    so a slow or unreachable database cannot stall the API. Failures degrade
    gracefully — the endpoint still returns 200 with partial information and
    the top-level ``status`` flips to ``"degraded"`` so upstream monitors can
    alert on the difference.

    The legacy keys (``total_assets``, ``last_log_timestamp``, ``scan``,
    ``zeek_process``) remain in the response for backward compatibility with
    existing clients — new clients should read the structured sub-objects.
    """
    pool: asyncpg.Pool | None = getattr(app.state, "pool", None)
    scan_svc: ScanService | None = getattr(app.state, "scan_service", None)

    # ── Database ────────────────────────────────────────────────────────
    db_connected = False
    db_latency_ms: float | None = None
    db_error: str | None = None
    total_assets = 0
    classified_assets = 0
    unknown_assets = 0
    last_seen_ts = None

    if pool is not None:
        started = time.perf_counter()
        try:
            async with pool.acquire(timeout=_HEALTH_DB_TIMEOUT_S) as conn:
                # Cheap liveness probe first — proves the socket works.
                db_connected = bool(await asyncio.wait_for(
                    conn.fetchval("SELECT true"),
                    timeout=_HEALTH_DB_TIMEOUT_S,
                ))

                # Pull asset counts — filtered by LOCAL_SUBNETS to match the
                # assets page.  Only counts assets that have a primary IP in
                # one of the configured local subnets.
                cfg = getattr(app.state, "config", None)
                subnets = cfg.local_subnets_list if cfg else ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                row = await asyncio.wait_for(
                    conn.fetchrow(
                        """
                        SELECT
                            COUNT(*)                                      AS total,
                            COUNT(*) FILTER (
                                WHERE i.device_type IS NOT NULL
                                  AND i.device_type <> 'Unknown'
                            )                                             AS classified,
                            COUNT(*) FILTER (
                                WHERE i.device_type IS NULL
                                   OR i.device_type = 'Unknown'
                            )                                             AS unknown,
                            MAX(a.last_seen)                              AS last_seen
                        FROM assets a
                        JOIN asset_ips ai ON ai.asset_id = a.id
                                         AND ai.is_primary = true
                        LEFT JOIN LATERAL (
                            SELECT device_type
                            FROM inference_results ir
                            WHERE ir.asset_id = a.id
                            ORDER BY ir.created_at DESC
                            LIMIT 1
                        ) i ON true
                        WHERE ai.ip_address <<= ANY($1::inet[])
                        """,
                        subnets,
                    ),
                    timeout=_HEALTH_DB_TIMEOUT_S,
                )
                if row is not None:
                    total_assets      = int(row["total"] or 0)
                    classified_assets = int(row["classified"] or 0)
                    unknown_assets    = int(row["unknown"] or 0)
                    last_seen_ts      = row["last_seen"]
            db_latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
        except asyncio.TimeoutError:
            db_error = "query timeout"
        except asyncpg.PostgresError as exc:
            db_error = f"postgres: {exc.__class__.__name__}"
        except Exception as exc:
            # Never let /health raise — the caller needs a verdict, not a 500.
            db_error = f"{exc.__class__.__name__}: {exc}"

    # ── Scan / ingestion ─────────────────────────────────────────────────
    scan_status: dict = {"status": "unavailable"}
    events_per_sec = 0.0
    ingestion_status = "stopped"

    if scan_svc is not None:
        try:
            scan_status = scan_svc.get_status()
            events_per_sec = float(scan_status.get("ingestion_rate") or 0.0)
            ingestion_status = "running" if scan_status.get("running") else "stopped"
        except Exception as exc:
            logger.warning("health: scan_service.get_status() failed", extra={"error": str(exc)})

    # ── Zeek — external sensor (runs on host OS, not managed by app) ───
    # Check if log directory has recent files as a proxy for Zeek health
    zeek_log_dir = getattr(app.state, "config", None)
    zeek_log_path = getattr(zeek_log_dir, "zeek_log_dir", "/logs") if zeek_log_dir else "/logs"
    zeek_logs_exist = False
    try:
        from pathlib import Path
        log_path = Path(zeek_log_path)
        if log_path.exists():
            zeek_logs_exist = any(log_path.glob("*.log"))
    except Exception:
        pass

    last_log_iso = last_seen_ts.isoformat() if last_seen_ts else None
    is_healthy = db_connected and db_error is None

    database_block: dict = {
        "connected": db_connected,
        "latency_ms": db_latency_ms,
    }
    if db_error is not None:
        database_block["error"] = db_error

    zeek_block: dict = {
        "running": zeek_logs_exist,
        "note": "external sensor — Zeek runs on host OS, not managed by this app",
    }

    return {
        "status": "ok" if is_healthy else "degraded",
        "database": database_block,
        "zeek": zeek_block,
        "ingestion": {
            "status": ingestion_status,
            "events_per_sec": events_per_sec,
            "last_log_timestamp": last_log_iso,
        },
        "assets": {
            "total": total_assets,
            "classified": classified_assets,
            "unknown": unknown_assets,
        },
        # ── Legacy keys (kept for backward compatibility) ──
        "total_assets": total_assets,
        "last_log_timestamp": last_log_iso,
        "scan": scan_status,
        "zeek_process": zeek_block,
    }
