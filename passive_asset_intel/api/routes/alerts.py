"""Alert endpoints — GET /api/alerts, PATCH /api/alerts/{id}."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from passive_asset_intel.api.deps import get_conn
from passive_asset_intel.api.models import AlertUpdateRequest
from passive_asset_intel.auth.deps import require_admin, require_analyst
from passive_asset_intel.services.alert_service import (
    get_alert_counts,
    list_alerts,
    update_alert_status,
)

router = APIRouter(prefix="/api", tags=["alerts"])

VALID_STATUSES = {"new", "investigating", "resolved", "false_positive"}
VALID_TYPES = {"new_asset", "unusual_port", "external_connection", "vulnerability"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@router.get("/alerts")
async def get_alerts(
    status: str | None = Query(None, description="Filter by status"),
    alert_type: str | None = Query(None, alias="type", description="Filter by alert type"),
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_analyst),
):
    """List alerts with optional filters for status, type, and severity.

    Returns ``{ items: [...], total: N }`` for pagination.
    """
    try:
        # Validate filter values
        if status and status not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        if alert_type and alert_type not in VALID_TYPES:
            raise HTTPException(status_code=400, detail=f"Invalid type: {alert_type}")
        if severity and severity not in VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

        return await list_alerts(
            conn,
            status=status,
            alert_type=alert_type,
            severity=severity,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "internal"})


@router.patch("/alerts/{alert_id}")
async def patch_alert(
    alert_id: str,
    body: AlertUpdateRequest,
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_analyst),
):
    """Update an alert's status and optional note (e.g. false_positive rationale)."""
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    try:
        result = await update_alert_status(conn, alert_id, body.status, body.note)
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return result
    except HTTPException:
        raise
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})


@router.get("/alerts/counts")
async def alert_counts(
    conn: asyncpg.Connection = Depends(get_conn),
    _user: dict = Depends(require_analyst),
):
    """Return alert counts grouped by status and severity."""
    try:
        return await get_alert_counts(conn)
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})
