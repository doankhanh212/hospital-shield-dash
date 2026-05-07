"""XDR correlation engine — promotes multi-anomaly bursts to incidents.

Rule: if an asset accumulates ≥ 2 distinct anomaly types with last_seen
within the past 5 minutes, create/update an XDR incident.
"""

from __future__ import annotations

import asyncpg

from passive_asset_intel.utils.logger import setup_logger
from passive_asset_intel.xdr.incident import build_incident
from passive_asset_intel.xdr.storage import upsert_incident

logger = setup_logger(__name__)

_WINDOW = "5 minutes"
_MIN_TYPES = 2


async def correlate(pool: asyncpg.Pool, asset_id: str) -> None:
    """Evaluate recent anomalies for *asset_id* and raise an incident if warranted.

    Queries xdr_anomalies for all distinct anomaly types whose last_seen falls
    within the correlation window.  When the count reaches the threshold an
    incident is upserted (created or updated) via the storage layer.

    Args:
        pool:     Shared asyncpg connection pool.
        asset_id: Asset identifier to correlate (src_ip from Zeek logs).
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT type, severity, evidence
            FROM   xdr_anomalies
            WHERE  asset_id  = $1
              AND  last_seen > NOW() - INTERVAL '{_WINDOW}'
            """,
            asset_id,
        )

    if len(rows) < _MIN_TYPES:
        return

    anomalies = [dict(r) for r in rows]
    incident = build_incident(asset_id, anomalies)

    try:
        saved = await upsert_incident(pool, incident)
        logger.info(
            "XDR incident raised",
            extra={
                "asset_id":      asset_id,
                "incident_id":   str(saved["id"]),
                "severity":      saved["severity"],
                "anomaly_types": incident["anomaly_types"],
            },
        )
    except Exception:
        logger.exception(
            "Failed to upsert XDR incident",
            extra={"asset_id": asset_id, "anomaly_types": incident["anomaly_types"]},
        )
