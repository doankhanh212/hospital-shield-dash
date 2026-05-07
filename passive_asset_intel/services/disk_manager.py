"""Log-file and database record retention service.

Runs in the background on a fixed interval (default: every 6 hours) and:

1. Deletes Zeek log files (``*.log``, ``*.gz``, ``*.bz2``) older than
   ``log_retention_days`` from the configured log directory.
2. Purges high-volume telemetry DB rows (connections, dns_queries,
   http_sessions, tls_sessions) older than the same cutoff so the database
   does not grow unbounded over time.

Configuration (via environment / .env):
    LOG_RETENTION_DAYS  — default 7; minimum 1.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg

from passive_asset_intel.utils.config import Config
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

_MIN_RETENTION_DAYS: int = 1
_CLEANUP_INTERVAL_SECONDS: int = 6 * 3600  # 6 hours

# Tables with high row-volume that are safe to prune by timestamp
_PURGEABLE_TABLES: list[tuple[str, str]] = [
    ("connections", "timestamp"),
    ("dns_queries", "timestamp"),
    ("http_sessions", "timestamp"),
    ("tls_sessions", "timestamp"),
]

# Log file extensions produced by Zeek
_LOG_PATTERNS: list[str] = ["*.log", "*.gz", "*.bz2"]


class DiskManager:
    """Background task that enforces log-file and DB data retention.

    Start with :meth:`start` during application lifespan; stop with
    :meth:`stop` on shutdown.
    """

    def __init__(self, pool: asyncpg.Pool, config: Config) -> None:
        self._pool = pool
        self._config = config
        self._task: asyncio.Task | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Schedule the retention loop as a background asyncio task."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="disk-manager")
            logger.info(
                "DiskManager started",
                extra={
                    "retention_days": self._config.log_retention_days,
                    "interval_hours": _CLEANUP_INTERVAL_SECONDS // 3600,
                },
            )

    async def stop(self) -> None:
        """Cancel the background task and wait for it to finish."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("DiskManager stopped")

    # ── Main loop ─────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        """Run cleanup immediately, then every ``_CLEANUP_INTERVAL_SECONDS``."""
        while True:
            try:
                await self._run_cleanup()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("DiskManager cleanup cycle raised an unexpected error")
            await asyncio.sleep(_CLEANUP_INTERVAL_SECONDS)

    async def _run_cleanup(self) -> None:
        # Retention disabled when LOG_RETENTION_DAYS <= 0 — keep everything,
        # let the analyst purge manually via /api/data/purge.
        if self._config.log_retention_days <= 0:
            logger.info(
                "DiskManager: auto-purge disabled (LOG_RETENTION_DAYS=0)",
            )
            return
        retention_days = max(self._config.log_retention_days, _MIN_RETENTION_DAYS)
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        logger.info(
            "DiskManager: cleanup cycle starting",
            extra={"cutoff": cutoff.isoformat(), "retention_days": retention_days},
        )
        await self._cleanup_log_files(cutoff)
        await self._cleanup_db_records(cutoff)

    # ── Log file retention ─────────────────────────────────────────────────

    async def _cleanup_log_files(self, cutoff: datetime) -> None:
        """Delete log files older than *cutoff* from the Zeek log directory.

        Runs the file-system scan in a thread pool executor to avoid blocking
        the event loop.
        """
        log_dir = self._config.zeek_log_dir
        if not log_dir:
            logger.debug("DiskManager: no log directory configured — skipping file cleanup")
            return

        target = Path(log_dir)
        if not target.exists():
            return

        # naive datetime for comparison against st_mtime (which has no tzinfo)
        cutoff_naive = cutoff.replace(tzinfo=None)

        def _scan_and_delete() -> int:
            deleted = 0
            for pattern in _LOG_PATTERNS:
                for path in target.rglob(pattern):
                    try:
                        mtime = datetime.fromtimestamp(path.stat().st_mtime)
                        if mtime < cutoff_naive:
                            path.unlink()
                            deleted += 1
                    except FileNotFoundError:
                        pass  # race: already deleted by another process
                    except Exception as exc:
                        logger.warning(
                            "DiskManager: cannot delete %s — %s", path, exc
                        )
            return deleted

        loop = asyncio.get_event_loop()
        deleted = await loop.run_in_executor(None, _scan_and_delete)
        logger.info(
            "DiskManager: log file cleanup complete",
            extra={"deleted_files": deleted, "log_dir": log_dir},
        )

    # ── DB record retention ────────────────────────────────────────────────

    async def _cleanup_db_records(self, cutoff: datetime) -> None:
        """DELETE telemetry rows older than *cutoff* from high-volume tables.

        Each table is pruned in its own statement so a failure in one table
        does not block the others.
        """
        cutoff_naive = cutoff.replace(tzinfo=None)

        for table, ts_col in _PURGEABLE_TABLES:
            try:
                async with self._pool.acquire() as conn:
                    # Table and column names come from a hardcoded list, not user input,
                    # so f-string interpolation here does not create an injection risk.
                    result = await conn.execute(
                        f"DELETE FROM {table} WHERE {ts_col} < $1",  # noqa: S608
                        cutoff_naive,
                    )
                    logger.info(
                        "DiskManager: DB purge complete",
                        extra={"table": table, "result": result},
                    )
            except asyncpg.PostgresError:
                logger.exception(
                    "DiskManager: DB purge failed for table %s", table
                )
