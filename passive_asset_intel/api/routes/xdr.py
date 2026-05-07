"""XDR endpoints — anomalies, incidents, and settings (API key) management."""

from __future__ import annotations

import os

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from passive_asset_intel.api.deps import get_conn, get_pool
from passive_asset_intel.auth.deps import require_admin, require_analyst
from passive_asset_intel.utils.config import load_config  # ensures .env is read
from passive_asset_intel.xdr.settings import (
    delete_setting,
    get_setting,
    list_settings,
    set_setting,
)
from passive_asset_intel.xdr.incident import build_timeline
from passive_asset_intel.xdr.storage import (
    VALID_STATUSES,
    add_anomaly_note,
    assign_anomaly,
    fetch_anomalies,
    fetch_audit_log,
    fetch_incidents,
    update_anomaly_status,
)


# ── Dev-mode auth bypass ─────────────────────────────────────────────────────
# When XDR_DEV_OPEN=1, /api/xdr/anomalies and /api/xdr/incidents skip auth.
# Settings endpoints stay protected even in dev mode (they accept secrets).
# We use a runtime-evaluated dependency so .env loaded by lifespan applies.
load_config()  # idempotent; populates os.environ from .env at import time


async def _read_user_runtime() -> dict:
    """Resolved at request time — checks XDR_DEV_OPEN every call."""
    if os.getenv("XDR_DEV_OPEN", "0") == "1":
        return {"username": "dev", "role": "analyst"}
    # Fall through to the real guard
    from fastapi import Request
    raise HTTPException(  # only reached if env disabled mid-process
        status_code=401, detail="Not authenticated",
    )


def _read_user(*args, **kwargs):  # type: ignore[no-redef]
    """Static dispatcher chosen at import time, after load_config()."""
    raise NotImplementedError  # replaced below


if os.getenv("XDR_DEV_OPEN", "0") == "1":
    async def _read_user() -> dict:  # type: ignore[no-redef]
        return {"username": "dev", "role": "analyst"}
else:
    _read_user = require_analyst  # type: ignore[assignment]


router = APIRouter(prefix="/api/xdr", tags=["xdr"])

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_TYPES      = {"port_scan", "dns_spike", "data_exfiltration",
                     "rare_ja3", "rare_domain", "rogue_device"}
_VALID_SETTING_KEYS = {"VT_API_KEY", "ABUSEIPDB_API_KEY"}


class SettingUpsert(BaseModel):
    key:   str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)


class StatusBody(BaseModel):
    status: str = Field(..., min_length=3, max_length=16)


class AssignBody(BaseModel):
    user: str | None = Field(None, max_length=64,
                             description="User to assign; null/empty unassigns")


class NoteBody(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


def _actor_from_user(user: dict | None) -> str | None:
    if not user:
        return None
    return user.get("username") or "unknown"


@router.get("/anomalies")
async def get_anomalies(
    asset_id:      str | None = Query(None, description="Filter by asset IP"),
    severity:      str | None = Query(None, description="critical|high|medium|low"),
    anomaly_type:  str | None = Query(None, alias="type",
                                      description="port_scan|dns_spike|data_exfiltration"),
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0,   ge=0),
    conn:   asyncpg.Connection = Depends(get_conn),
    _user:  dict               = Depends(_read_user),
):
    """Paginated list of XDR anomalies with optional filters.

    Returns ``{ items: [...], total: N }``.
    """
    if severity and severity not in _VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if anomaly_type and anomaly_type not in _VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type: {anomaly_type}")

    try:
        return await fetch_anomalies(
            conn,
            asset_id=asset_id,
            severity=severity,
            anomaly_type=anomaly_type,
            limit=limit,
            offset=offset,
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "internal"})


@router.get("/incidents")
async def get_incidents(
    asset_id: str | None = Query(None, description="Filter by asset IP"),
    severity: str | None = Query(None, description="critical|high|medium|low"),
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0,   ge=0),
    conn:   asyncpg.Connection = Depends(get_conn),
    _user:  dict               = Depends(_read_user),
):
    """Paginated list of XDR incidents with optional filters.

    Returns ``{ items: [...], total: N }``.
    """
    if severity and severity not in _VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    try:
        return await fetch_incidents(
            conn,
            asset_id=asset_id,
            severity=severity,
            limit=limit,
            offset=offset,
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "internal"})


# ── Triage actions ───────────────────────────────────────────────────────────

@router.patch("/anomalies/{anomaly_id}/status")
async def patch_anomaly_status(
    anomaly_id: str,
    body:   StatusBody,
    pool:   asyncpg.Pool = Depends(get_pool),
    user:   dict         = Depends(_read_user),
):
    """Change an anomaly's triage status.  Allowed values:
    ``new | investigating | escalated | resolved | false_positive``.
    """
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status: {body.status}. Allowed: {sorted(VALID_STATUSES)}",
        )
    try:
        updated = await update_anomaly_status(
            pool, anomaly_id, body.status, _actor_from_user(user),
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    if updated is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return _serialize_anomaly(updated)


@router.post("/anomalies/{anomaly_id}/assign")
async def post_anomaly_assign(
    anomaly_id: str,
    body:   AssignBody,
    pool:   asyncpg.Pool = Depends(get_pool),
    user:   dict         = Depends(_read_user),
):
    """Assign (or unassign with empty/null user) an anomaly to an analyst."""
    target = (body.user or "").strip() or None
    try:
        updated = await assign_anomaly(pool, anomaly_id, target, _actor_from_user(user))
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    if updated is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return _serialize_anomaly(updated)


@router.post("/anomalies/{anomaly_id}/note")
async def post_anomaly_note(
    anomaly_id: str,
    body:   NoteBody,
    pool:   asyncpg.Pool = Depends(get_pool),
    user:   dict         = Depends(_read_user),
):
    """Append (overwrite) an analyst note on an anomaly.  The full prior text
    is preserved in the audit log."""
    try:
        updated = await add_anomaly_note(pool, anomaly_id, body.note, _actor_from_user(user))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    if updated is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return _serialize_anomaly(updated)


# ── Audit log + timeline ─────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_log(
    entity_id: str | None = Query(None, description="Filter to one entity"),
    asset_id:  str | None = Query(None, description="Filter to all anomalies for an asset (IP)"),
    limit: int = Query(200, ge=1, le=1000),
    conn:  asyncpg.Connection = Depends(get_conn),
    _user: dict               = Depends(_read_user),
):
    """Return audit log rows newest-first.  Supports filtering by entity or
    by asset (joins through xdr_anomalies)."""
    try:
        items = await fetch_audit_log(
            conn,
            entity_type='anomaly' if entity_id else None,
            entity_id=entity_id,
            asset_id=asset_id,
            limit=limit,
        )
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    return {"items": items, "total": len(items)}


@router.get("/assets/{asset_id}/timeline")
async def get_asset_timeline(
    asset_id: str,
    limit: int = Query(100, ge=1, le=500),
    pool:  asyncpg.Pool = Depends(get_pool),
    _user: dict          = Depends(_read_user),
):
    """Unified timeline (anomaly + action events) for one asset, newest-first."""
    try:
        events = await build_timeline(pool, asset_id, limit=limit)
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    return {"items": events, "total": len(events)}


def _serialize_anomaly(row: dict) -> dict:
    """Coerce types from a raw asyncpg row dict into JSON-friendly form."""
    import json as _json
    out = dict(row)
    for k in ("id", "asset_uuid", "first_seen", "last_seen", "updated_at"):
        if out.get(k) is not None:
            out[k] = str(out[k])
    if isinstance(out.get("evidence"), str):
        try: out["evidence"] = _json.loads(out["evidence"])
        except (ValueError, TypeError): pass
    out["score"] = float(out.get("score") or 0.0)
    return out


# ── Settings (API keys) ──────────────────────────────────────────────────────

@router.get("/settings")
async def get_settings(
    pool:   asyncpg.Pool = Depends(get_pool),
    _user:  dict         = Depends(require_admin),
):
    """List all XDR settings.  Values are masked except for the last 4 chars."""
    try:
        return {"items": await list_settings(pool)}
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})


@router.post("/settings")
async def upsert_setting(
    body:   SettingUpsert,
    pool:   asyncpg.Pool = Depends(get_pool),
    _user:  dict         = Depends(require_admin),
):
    """Create or replace an XDR setting (e.g. VT_API_KEY, ABUSEIPDB_API_KEY).

    Returns ``{ key, value (masked), updated_at }``.
    """
    if body.key not in _VALID_SETTING_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown key: {body.key}. Allowed: {sorted(_VALID_SETTING_KEYS)}",
        )
    try:
        saved = await set_setting(pool, body.key, body.value)
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})

    v = saved["value"]
    masked = "***" + v[-4:] if v and len(v) > 4 else "***"
    return {
        "key":        saved["key"],
        "value":      masked,
        "updated_at": saved["updated_at"].isoformat() if saved["updated_at"] else None,
    }


@router.delete("/settings/{key}")
async def remove_setting(
    key:    str,
    pool:   asyncpg.Pool = Depends(get_pool),
    _user:  dict         = Depends(require_admin),
):
    """Delete an XDR setting.  404 if the key does not exist."""
    if key not in _VALID_SETTING_KEYS:
        raise HTTPException(status_code=400, detail=f"Unknown key: {key}")
    try:
        deleted = await delete_setting(pool, key)
    except asyncpg.PostgresError as exc:
        raise HTTPException(status_code=500, detail={"error": str(exc), "type": "database"})
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Setting not found: {key}")
    return {"deleted": key}
