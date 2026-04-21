from __future__ import annotations

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


async def ensure_alert_indexes(pool: asyncpg.Pool) -> None:
    """Ensure alert dedup indexes match current alert semantics.

    Historical schema used a single unique index on
    ``(alert_type, source_ip, hour(created_at))`` for *all* alert types. That
    works for bursty runtime alerts, but it breaks vulnerability alerts because
    an asset can legitimately have many CVEs within the same hour.

    Current policy:
    - non-vulnerability alerts: dedup by ``alert_type + source_ip + hour``
    - vulnerability alerts: dedup by ``alert_type + asset_id + vulnerability_id``
    """
    async with pool.acquire() as conn:
        await conn.execute("DROP INDEX IF EXISTS uq_alerts_dedup")
        await conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_runtime_dedup
                ON alerts (
                    alert_type,
                    COALESCE(source_ip, ''),
                    date_trunc('hour', created_at)
                )
                WHERE alert_type <> 'vulnerability'
            """
        )
        await conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_vulnerability_dedup
                ON alerts (
                    alert_type,
                    asset_id,
                    COALESCE(metadata->>'vulnerability_id', '')
                )
                WHERE alert_type = 'vulnerability'
            """
        )

    logger.info("Alert dedup indexes ensured")