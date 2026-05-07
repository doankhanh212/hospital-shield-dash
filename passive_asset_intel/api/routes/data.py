"""Data Management API — manual purge / retention controls.

Replaces the implicit "auto-delete after N days" behaviour with explicit,
analyst-driven cleanup.  All destructive endpoints support a ``dry_run``
flag that returns the *would-be* impact without actually deleting.

Endpoints:
    GET    /api/data/stats               counts overview
    GET    /api/data/retention           current auto-purge setting
    PUT    /api/data/retention           change retention (admin)
    POST   /api/data/purge               filtered purge (analyst, dry_run-able)
    DELETE /api/data/asset/{ip}          delete one asset (cascade)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from passive_asset_intel.api.deps import get_conn, get_config, get_pool
from passive_asset_intel.auth.deps import require_admin, require_analyst

router = APIRouter(prefix="/api/data", tags=["data"])


# ── Request models ───────────────────────────────────────────────────────────

class PurgeBody(BaseModel):
    """Filter set for /api/data/purge.  All filters AND together."""
    older_than_days:        int  | None = Field(None, ge=0, le=3650)
    only_external:          bool | None = False
    only_multicast:         bool | None = False
    only_ipv6_link_local:   bool | None = False
    only_ipv6:              bool | None = False
    subnet:                 str  | None = Field(None, max_length=64,
                                                description="CIDR — e.g. 192.168.1.0/24")
    delete_all:             bool | None = False
    dry_run:                bool        = True


class RetentionBody(BaseModel):
    days: int = Field(..., ge=0, le=3650,
                      description="0 disables auto-purge entirely")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _local_subnets(config) -> list[str]:
    return getattr(config, "local_subnets_list", []) or [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    ]


def _build_purge_clause(body: PurgeBody, config, params: list[Any]) -> str:
    """Translate PurgeBody into a SQL WHERE fragment + push values into params."""
    clauses: list[str] = []

    if body.older_than_days is not None:
        params.append(body.older_than_days)
        clauses.append(f"a.last_seen < NOW() - INTERVAL '1 day' * ${len(params)}")

    if body.only_external:
        # Anything NOT in any local subnet
        subnets = _local_subnets(config)
        params.append(subnets)
        clauses.append(
            f"NOT EXISTS (SELECT 1 FROM unnest(${len(params)}::cidr[]) s "
            f"WHERE ai.ip_address << s)"
        )

    if body.only_multicast:
        # IPv4 224.0.0.0/4 ∪ IPv6 ff00::/8
        clauses.append(
            "(ai.ip_address << '224.0.0.0/4'::cidr "
            " OR ai.ip_address << 'ff00::/8'::cidr)"
        )

    if body.only_ipv6_link_local:
        clauses.append("ai.ip_address << 'fe80::/10'::cidr")

    if body.only_ipv6:
        clauses.append("family(ai.ip_address) = 6")

    if body.subnet:
        params.append(body.subnet)
        clauses.append(f"ai.ip_address << ${len(params)}::cidr")

    if not clauses and not body.delete_all:
        # Safety: never run a no-filter purge unless delete_all is explicit
        raise HTTPException(
            status_code=400,
            detail="Specify at least one filter, or set delete_all=true",
        )

    if body.delete_all and not clauses:
        return "TRUE"

    return " AND ".join(clauses)


# ── Stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(
    conn:   asyncpg.Connection = Depends(get_conn),
    config = Depends(get_config),
    _user:  dict               = Depends(require_analyst),
):
    """Counts per category — useful as a 'preview' for the analyst."""
    subnets = _local_subnets(config)

    row = await conn.fetchrow(
        """
        WITH ip_features AS (
            SELECT a.id AS asset_id,
                   ai.ip_address,
                   EXISTS(SELECT 1 FROM unnest($1::cidr[]) s WHERE ai.ip_address << s) AS is_local,
                   (ai.ip_address << '224.0.0.0/4'::cidr OR ai.ip_address << 'ff00::/8'::cidr) AS is_multicast,
                   (ai.ip_address << 'fe80::/10'::cidr) AS is_link_local,
                   (family(ai.ip_address) = 6) AS is_ipv6
            FROM   assets a
            JOIN   asset_ips ai ON ai.asset_id = a.id
        )
        SELECT
            (SELECT count(*) FROM assets)               AS total_assets,
            (SELECT count(*) FROM asset_ips)            AS total_ips,
            (SELECT count(*) FROM connections)          AS connections,
            (SELECT count(*) FROM dns_queries)          AS dns_queries,
            (SELECT count(*) FROM tls_sessions)         AS tls_sessions,
            (SELECT count(*) FROM http_sessions)        AS http_sessions,
            (SELECT count(*) FROM xdr_anomalies)        AS xdr_anomalies,
            (SELECT count(*) FROM xdr_incidents)        AS xdr_incidents,
            (SELECT count(*) FROM xdr_audit_log)        AS xdr_audit_log,
            COUNT(*) FILTER (WHERE is_local)            AS internal_ips,
            COUNT(*) FILTER (WHERE NOT is_local AND NOT is_multicast)  AS external_ips,
            COUNT(*) FILTER (WHERE is_multicast)        AS multicast_ips,
            COUNT(*) FILTER (WHERE is_link_local)       AS link_local_ips,
            COUNT(*) FILTER (WHERE is_ipv6)             AS ipv6_ips
        FROM ip_features
        """,
        subnets,
    )
    return {k: int(v or 0) for k, v in dict(row).items()}


# ── Retention ────────────────────────────────────────────────────────────────

@router.get("/retention")
async def get_retention(
    config = Depends(get_config),
    _user:  dict = Depends(require_analyst),
):
    days = int(getattr(config, "log_retention_days", 0))
    return {
        "auto_purge_enabled": days > 0,
        "retention_days":     days,
        "description":        "0 = keep everything; > 0 = auto-delete data older than N days",
    }


@router.put("/retention")
async def set_retention(
    body:   RetentionBody,
    config = Depends(get_config),
    _user:  dict = Depends(require_admin),
):
    """Update LOG_RETENTION_DAYS in the running .env file (and live config).

    Requires admin role.  Takes effect immediately for the next DiskManager
    cleanup cycle (the next 6-hour tick) — process restart not required.
    """
    env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
    if not env_path.exists():
        raise HTTPException(status_code=500, detail=f".env not found at {env_path}")

    text = env_path.read_text()
    new_line = f"LOG_RETENTION_DAYS={body.days}"
    if "LOG_RETENTION_DAYS=" in text:
        text = "\n".join(
            (new_line if l.startswith("LOG_RETENTION_DAYS=") else l)
            for l in text.splitlines()
        ) + ("\n" if text.endswith("\n") else "")
    else:
        if not text.endswith("\n"): text += "\n"
        text += new_line + "\n"
    env_path.write_text(text)

    # Mutate the in-memory frozen config via __dict__ trick — config is
    # a frozen dataclass so we use object.__setattr__.
    try:
        object.__setattr__(config, "log_retention_days", body.days)
    except Exception:
        pass

    # Also reflect in the process env so any subsequent load_config sees it
    os.environ["LOG_RETENTION_DAYS"] = str(body.days)

    return {
        "auto_purge_enabled": body.days > 0,
        "retention_days":     body.days,
        "applied":            True,
    }


# ── Purge ────────────────────────────────────────────────────────────────────

@router.post("/purge")
async def purge(
    body:   PurgeBody,
    pool:   asyncpg.Pool = Depends(get_pool),
    config = Depends(get_config),
    _user:  dict         = Depends(require_admin),
):
    """Filtered, transactional purge of assets matching the criteria.

    Cascade: deleting an asset removes its rows in ``asset_ips`` (FK CASCADE),
    ``connections``, ``dns_queries``, ``tls_sessions``, ``fingerprints``,
    ``inference_results`` (asset-tied tables).  XDR anomalies that referenced
    the asset have their ``asset_uuid`` set to NULL but the alert history is
    kept (audit trail).

    Body fields are AND-combined.  Pass ``dry_run=true`` to preview impact.
    """
    params: list[Any] = []
    where = _build_purge_clause(body, config, params)

    async with pool.acquire() as conn:
        # Find target asset_ids first (works for both dry_run and real)
        target_rows = await conn.fetch(
            f"""
            SELECT DISTINCT a.id
            FROM   assets a
            JOIN   asset_ips ai ON ai.asset_id = a.id
            WHERE  {where}
            """,
            *params,
        )
        target_ids = [r["id"] for r in target_rows]
        target_count = len(target_ids)

        # Count what would cascade for the preview
        if target_count > 0:
            preview = await conn.fetchrow(
                """
                SELECT
                    (SELECT count(*) FROM connections
                       WHERE src_asset_id = ANY($1::uuid[])
                          OR dst_asset_id = ANY($1::uuid[]))      AS connections,
                    (SELECT count(*) FROM dns_queries    WHERE asset_id = ANY($1::uuid[])) AS dns_queries,
                    (SELECT count(*) FROM tls_sessions   WHERE asset_id = ANY($1::uuid[])) AS tls_sessions,
                    (SELECT count(*) FROM http_sessions  WHERE asset_id = ANY($1::uuid[])) AS http_sessions
                """,
                target_ids,
            )
            preview = {k: int(v or 0) for k, v in dict(preview).items()}
        else:
            preview = {"connections": 0, "dns_queries": 0,
                       "tls_sessions": 0, "http_sessions": 0}

        deleted = {"assets": 0, **preview}

        if body.dry_run or target_count == 0:
            return {"dry_run": True, "matched_assets": target_count,
                    "would_delete": {"assets": target_count, **preview}}

        # Real delete — single transaction
        async with conn.transaction():
            # Detach XDR anomaly linkage so history is preserved
            await conn.execute(
                "UPDATE xdr_anomalies SET asset_uuid = NULL WHERE asset_uuid = ANY($1::uuid[])",
                target_ids,
            )
            await conn.execute(
                "UPDATE xdr_incidents SET asset_uuid = NULL WHERE asset_uuid = ANY($1::uuid[])",
                target_ids,
            )
            # connections uses src_asset_id / dst_asset_id (not asset_id).
            # Each optional delete runs in its own savepoint so an undefined
            # table/column failure does not poison the surrounding tx.
            async with conn.transaction():
                try:
                    await conn.execute(
                        """
                        DELETE FROM connections
                        WHERE src_asset_id = ANY($1::uuid[])
                           OR dst_asset_id = ANY($1::uuid[])
                        """,
                        target_ids,
                    )
                except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
                    raise  # rollback this savepoint

            for tbl in ("dns_queries", "tls_sessions",
                        "http_sessions", "fingerprints", "inference_results",
                        "inference_evidence", "inference_anomalies",
                        "asset_vulnerabilities", "asset_tags"):
                try:
                    async with conn.transaction():
                        await conn.execute(
                            f"DELETE FROM {tbl} WHERE asset_id = ANY($1::uuid[])",
                            target_ids,
                        )
                except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
                    pass  # optional / column-mismatch — skip cleanly
            # Finally drop the assets — asset_ips/asset_hostnames cascade via FK
            res = await conn.execute(
                "DELETE FROM assets WHERE id = ANY($1::uuid[])",
                target_ids,
            )
            try:
                deleted["assets"] = int(res.split()[-1])
            except (ValueError, IndexError):
                deleted["assets"] = target_count

    return {"dry_run": False, "matched_assets": target_count,
            "deleted": deleted}


# ── Single-asset delete ──────────────────────────────────────────────────────

@router.delete("/asset/{ip}")
async def delete_asset_by_ip(
    ip:    str,
    pool:  asyncpg.Pool = Depends(get_pool),
    _user: dict         = Depends(require_admin),
):
    """Delete every asset bound to *ip* (cascade)."""
    async with pool.acquire() as conn:
        try:
            target_ids_rows = await conn.fetch(
                "SELECT DISTINCT asset_id FROM asset_ips WHERE ip_address = $1::inet",
                ip,
            )
        except (asyncpg.DataError, ValueError):
            raise HTTPException(status_code=400, detail=f"Invalid IP: {ip}")

        target_ids = [r["asset_id"] for r in target_ids_rows]
        if not target_ids:
            raise HTTPException(status_code=404, detail=f"No asset found for {ip}")

        async with conn.transaction():
            await conn.execute(
                "UPDATE xdr_anomalies SET asset_uuid = NULL WHERE asset_uuid = ANY($1::uuid[])",
                target_ids,
            )
            await conn.execute(
                "UPDATE xdr_incidents SET asset_uuid = NULL WHERE asset_uuid = ANY($1::uuid[])",
                target_ids,
            )
            try:
                async with conn.transaction():
                    await conn.execute(
                        """
                        DELETE FROM connections
                        WHERE src_asset_id = ANY($1::uuid[])
                           OR dst_asset_id = ANY($1::uuid[])
                        """,
                        target_ids,
                    )
            except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
                pass
            for tbl in ("dns_queries", "tls_sessions",
                        "http_sessions", "fingerprints", "inference_results",
                        "inference_evidence", "inference_anomalies"):
                try:
                    async with conn.transaction():
                        await conn.execute(
                            f"DELETE FROM {tbl} WHERE asset_id = ANY($1::uuid[])",
                            target_ids,
                        )
                except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
                    pass
            await conn.execute(
                "DELETE FROM assets WHERE id = ANY($1::uuid[])",
                target_ids,
            )
    return {"deleted_ip": ip, "deleted_assets": len(target_ids)}
