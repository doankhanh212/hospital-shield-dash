"""Async PostgreSQL connection pool management using asyncpg."""

import asyncio
from typing import Optional

import asyncpg

from passive_asset_intel.utils.config import Config
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


class Database:
    """Manages an asyncpg connection pool for the application.

    Usage::

        db = Database(config)
        await db.connect()
        async with db.pool.acquire() as conn:
            await conn.fetch("SELECT 1")
        await db.disconnect()
    """

    def __init__(self, config: Config) -> None:
        """Initialize the Database wrapper.

        Args:
            config: Application configuration containing DB credentials and pool sizes.
        """
        self._config = config
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        """Create the asyncpg connection pool.

        Retries up to 3 times with exponential backoff on failure.
        """
        cfg = self._config
        for attempt in range(1, 4):
            try:
                self.pool = await asyncpg.create_pool(
                    host=cfg.db_host,
                    port=cfg.db_port,
                    database=cfg.db_name,
                    user=cfg.db_user,
                    password=cfg.db_password,
                    min_size=cfg.db_pool_min,
                    max_size=cfg.db_pool_max,
                    statement_cache_size=0,  # avoid prepared-stmt type conflicts on re-runs
                )
                logger.info(
                    "Database pool created",
                    extra={"host": cfg.db_host, "port": cfg.db_port, "db": cfg.db_name},
                )
                return
            except (asyncpg.PostgresError, OSError) as exc:
                wait = 2**attempt
                logger.warning(
                    "Database connection failed, retrying",
                    extra={"attempt": attempt, "wait_seconds": wait, "error": str(exc)},
                )
                if attempt == 3:
                    raise
                await asyncio.sleep(wait)

    async def disconnect(self) -> None:
        """Gracefully close the connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Database pool closed")
            self.pool = None
