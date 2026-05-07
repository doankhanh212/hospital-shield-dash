"""SOC Control Panel API — unified ingestion control & live system metrics.

Wraps the existing in-process ``ScanService`` (mounted on ``app.state``) so the
control panel does not spawn a competing subprocess and reuses the same DB pool.

Endpoints:
    GET  /api/soc/status   — quick state probe (running / stopped / pid / uptime)
    POST /api/soc/start    — kick off ingestion against the configured ZEEK_LOG_DIR
    POST /api/soc/stop     — graceful shutdown
    GET  /api/soc/metrics  — CPU / memory / EPS / log-file count / lag / breakdown
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from passive_asset_intel.api.deps import get_config
from passive_asset_intel.auth.deps import require_analyst

router = APIRouter(prefix="/api/soc", tags=["soc"])

_DEFAULT_LOG_DIR = "/usr/local/zeek/logs/current"
_LOG_FILES = ("conn.log", "dns.log", "ssl.log")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _scan_service(request: Request):
    svc = getattr(request.app.state, "scan_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Scan service not initialised")
    return svc


def _resolve_log_dir(config) -> Path:
    """Prefer the configured ZEEK_LOG_DIR; fall back to the well-known path."""
    cfg_dir = getattr(config, "zeek_log_dir", None)
    p = Path(cfg_dir) if cfg_dir else Path(_DEFAULT_LOG_DIR)
    if not p.exists():
        p = Path(_DEFAULT_LOG_DIR)
    return p


def _read_proc_self_status() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _process_metrics() -> dict[str, float]:
    """CPU% (system load /CPU count) and memory% for the backend process."""
    cpu_pct = 0.0
    mem_pct = 0.0

    try:
        load1, _, _ = os.getloadavg()
        n_cpu = max(1, os.cpu_count() or 1)
        cpu_pct = round((load1 / n_cpu) * 100.0, 1)
    except OSError:
        pass

    try:
        st = _read_proc_self_status()
        rss_kb = int((st.get("VmRSS", "0 kB").split()[0]))
        with open("/proc/meminfo", "r") as fh:
            total_kb = 0
            for line in fh:
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                    break
        if total_kb > 0:
            mem_pct = round((rss_kb / total_kb) * 100.0, 2)
    except (OSError, ValueError):
        pass

    return {"cpu": cpu_pct, "memory": mem_pct}


def _line_count_fast(path: Path) -> int:
    """Return line count of a (potentially large) log file without loading it."""
    n = 0
    try:
        with open(path, "rb") as fh:
            buf = fh.read(1 << 20)
            while buf:
                n += buf.count(b"\n")
                buf = fh.read(1 << 20)
    except OSError:
        return 0
    return n


def _eps_sampler(state: Any, log_dir: Path) -> tuple[float, dict[str, int], float | None]:
    """Compute EPS from the delta of total line count between successive calls.

    Returns: (eps, breakdown_per_log, lag_seconds_or_None)
    """
    breakdown: dict[str, int] = {}
    total = 0
    most_recent_mtime = 0.0
    for name in _LOG_FILES:
        p = log_dir / name
        c = _line_count_fast(p) if p.exists() else 0
        breakdown[name.replace(".log", "")] = c
        total += c
        try:
            most_recent_mtime = max(most_recent_mtime, p.stat().st_mtime)
        except OSError:
            pass

    now = time.monotonic()
    prev = getattr(state, "_soc_eps_sample", None)
    eps = 0.0
    if prev:
        prev_total, prev_t = prev
        dt = now - prev_t
        if dt > 0:
            delta = max(0, total - prev_total)
            eps = round(delta / dt, 2)
    state._soc_eps_sample = (total, now)

    lag: float | None = None
    if most_recent_mtime > 0:
        lag = round(time.time() - most_recent_mtime, 1)

    return eps, breakdown, lag


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(
    request: Request,
    _user:   dict = Depends(require_analyst),
):
    """Quick probe — running / stopped / pid / uptime in seconds."""
    svc    = _scan_service(request)
    status = svc.get_status()
    pid    = os.getpid() if status["running"] else None
    uptime = 0
    if status["running"] and status.get("started_at"):
        try:
            started = datetime.fromisoformat(status["started_at"])
            uptime  = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
        except ValueError:
            pass
    return {
        "status":  "running" if status["running"] else "stopped",
        "pid":     pid,
        "uptime":  uptime,
        "job_id":  status.get("job_id"),
        "started_at": status.get("started_at"),
    }


@router.post("/start")
async def start_ingestion(
    request: Request,
    config = Depends(get_config),
    _user:   dict = Depends(require_analyst),
):
    """Start ingestion against ``ZEEK_LOG_DIR``.

    Idempotent: if already running, returns 200 with the current status.
    """
    svc     = _scan_service(request)
    log_dir = str(_resolve_log_dir(config))
    if svc.running:
        return {"already_running": True, **svc.get_status()}
    try:
        # 'live' tails Zeek logs continuously so the panel stays LIVE.
        # File mode would finish in <1s and flip the panel to idle.
        result = await svc.start(mode="live", log_dir=log_dir)
    except RuntimeError as exc:
        # ScanService raises RuntimeError when already running — race tolerated
        return {"already_running": True, "detail": str(exc), **svc.get_status()}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


@router.post("/stop")
async def stop_ingestion(
    request: Request,
    _user:   dict = Depends(require_analyst),
):
    """Stop ingestion gracefully.  Idempotent — returns 200 if already stopped."""
    svc = _scan_service(request)
    if not svc.running:
        return {"already_stopped": True, **svc.get_status()}
    try:
        return await svc.stop()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/metrics")
async def get_metrics(
    request: Request,
    config = Depends(get_config),
    _user:   dict = Depends(require_analyst),
):
    """Live system metrics + ingestion health.

    Health rules:
        running + EPS == 0  → degraded
        running + EPS  > 0  → healthy
        stopped             → idle
    """
    svc        = _scan_service(request)
    state      = svc.get_status()
    log_dir    = _resolve_log_dir(config)
    eps, breakdown, lag = _eps_sampler(request.app.state, log_dir)
    proc       = _process_metrics()

    files = sorted(log_dir.glob("*.log")) if log_dir.exists() else []
    last_log_time = None
    if files:
        try:
            mt = max((f.stat().st_mtime for f in files), default=0)
            if mt > 0:
                last_log_time = datetime.fromtimestamp(mt, tz=timezone.utc).isoformat()
        except OSError:
            pass

    if state["running"]:
        health = "healthy" if eps > 0 else "degraded"
    else:
        health = "idle"

    return {
        "status":         "running" if state["running"] else "stopped",
        "health":         health,
        "cpu":            proc["cpu"],
        "memory":         proc["memory"],
        "events_per_sec": eps,
        "logs_ingested":  state.get("logs_processed", 0),
        "log_files":      len(files),
        "last_log_time":  last_log_time,
        "lag_seconds":    lag,
        "breakdown":      breakdown,
        "interface":      getattr(config, "zeek_interface", "") or "wlp2s0",
        "log_dir":        str(log_dir),
    }
