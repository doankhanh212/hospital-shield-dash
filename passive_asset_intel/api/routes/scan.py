"""Scan control endpoints — manage the ingestion pipeline.

Zeek runs externally on the host OS. These endpoints control only the
log-ingestion pipeline that reads Zeek's output files.

Routes:
    POST /api/scan/start    — start ingestion (file or live mode)  [admin]
    POST /api/scan/stop     — stop the running ingestion            [admin]
    POST /api/scan/restart  — stop then start with new params       [admin]
    GET  /api/scan/status   — current state + progress              [analyst]
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from passive_asset_intel.api.models import ScanStartRequest
from passive_asset_intel.auth.deps import require_admin, require_analyst

router = APIRouter(prefix="/api/scan", tags=["scan"])


def _get_scan_service(request: Request):
    """Retrieve the ScanService singleton from app.state."""
    svc = getattr(request.app.state, "scan_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Scan service not initialized")
    return svc


@router.post("/start")
async def start_scan(
    body: ScanStartRequest | None = None,
    scan_service=Depends(_get_scan_service),
    _user: dict = Depends(require_admin),
):
    """Start the ingestion pipeline.  **Requires admin role.**

    This does NOT start Zeek — Zeek runs independently on the host OS.
    It validates the log directory and begins reading Zeek log files.

    Request body (all fields optional):

    ```json
    {
        "mode": "file",          // "file" (default) or "live"
        "log_dir": "/logs",      // override ZEEK_LOG_DIR
        "interface": "eth0"      // informational only
    }
    ```
    """
    try:
        result = await scan_service.start(
            mode=body.mode if body else None,
            log_dir=body.log_dir if body else None,
            interface=body.interface if body else None,
        )
        return result
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/stop")
async def stop_scan(
    scan_service=Depends(_get_scan_service),
    _user: dict = Depends(require_admin),
):
    """Stop the currently running ingestion pipeline.  **Requires admin role.**"""
    result = await scan_service.stop()
    return result


@router.post("/restart")
async def restart_scan(
    body: ScanStartRequest | None = None,
    scan_service=Depends(_get_scan_service),
    _user: dict = Depends(require_admin),
):
    """Stop the current ingestion and start a new one.  **Requires admin role.**

    Accepts the same body as ``/start``. If the body is omitted, the previous
    mode, log_dir, and interface are reused.
    """
    try:
        result = await scan_service.restart(
            mode=body.mode if body else None,
            log_dir=body.log_dir if body else None,
            interface=body.interface if body else None,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
async def scan_status(
    scan_service=Depends(_get_scan_service),
    _user: dict = Depends(require_analyst),
):
    """Return the current ingestion state.  **Requires analyst role.**

    Response includes: ``mode``, ``running``, ``interface``, ``log_dir``,
    ``logs_processed``, ``assets_discovered``, timing fields.
    """
    return scan_service.get_status()
