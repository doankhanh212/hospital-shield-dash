"""Scan control service — manages background Zeek log ingestion + inference.

Supports two operating modes:

- **file** (default / development): reads static Zeek log files from a
  directory, processes them once and completes.

- **live** (production deployment): continuously polls a Zeek log directory
  (mounted read-only from the host where Zeek runs) at a fixed interval,
  ingesting new data and running inference after each cycle.

IMPORTANT: This service does NOT start, stop, or manage a Zeek process.
Zeek runs independently on the host OS (via ``zeekctl``) and its log
directory is simply mounted into the container at ``/logs``.

The ScanService is a singleton attached to ``app.state.scan_service`` during
the FastAPI lifespan.

Usage::

    svc = ScanService(pool, config)
    await svc.start()                          # file mode from config.zeek_log_dir
    await svc.start(mode="live", log_dir="/logs")  # live mode — poll logs
    status = svc.get_status()                  # returns current state dict
    await svc.stop()                           # graceful stop
    await svc.restart()                        # stop + start with same params
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import asyncpg

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.inference.engine import run_inference
from passive_asset_intel.parsers.conn_parser import ConnParser
from passive_asset_intel.parsers.dhcp_parser import DhcpParser
from passive_asset_intel.parsers.dns_parser import DnsParser
from passive_asset_intel.parsers.http_parser import HttpParser
from passive_asset_intel.parsers.ssl_parser import SslParser
from passive_asset_intel.utils.config import Config
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

ScanMode = Literal["file", "live"]

ALL_TYPES = ("dhcp", "conn", "dns", "http", "ssl")

PARSER_MAP = {
    "conn": ConnParser,
    "dns": DnsParser,
    "http": HttpParser,
    "ssl": SslParser,
    "dhcp": DhcpParser,
}

LOG_FILE_MAP = {
    "conn": "conn.log",
    "dns": "dns.log",
    "http": "http.log",
    "ssl": "ssl.log",
    "dhcp": "dhcp.log",
}

# Terminal statuses that should NOT be overwritten by stop()
_TERMINAL_STATUSES = frozenset({"completed", "failed"})

# How often (seconds) the live-mode loop polls for new log data
_LIVE_POLL_INTERVAL: float = 5.0


class ScanService:
    """Manages the lifecycle of background scan tasks.

    This service ONLY manages the ingestion pipeline. Zeek runs externally
    on the host OS — this service reads the log files Zeek produces.

    Attributes:
        mode:       Active scan mode ('file' or 'live').
        running:    True while a scan is active.
    """

    def __init__(self, pool: asyncpg.Pool, config: Config) -> None:
        self._pool = pool
        self._config = config

        # Serialize start/stop to prevent race conditions
        self._lock = asyncio.Lock()

        # Background asyncio task
        self._task: asyncio.Task | None = None
        self._cancel_event = asyncio.Event()

        # Backpressure: allows at most one ingest cycle to run concurrently.
        self._ingest_semaphore = asyncio.Semaphore(1)

        # Scan state
        self._mode: ScanMode = "file"
        self._interface: str | None = None
        self._log_dir: str | None = None
        self._status: str = "stopped"
        self._job_id: str | None = None
        self._logs_processed: int = 0
        self._assets_discovered: int = 0
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._error: str | None = None
        self._ingest_start_ts: float | None = None  # monotonic for rate calc

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._status == "running"

    @property
    def mode(self) -> ScanMode:
        return self._mode

    # ── Public API ─────────────────────────────────────────────────────────

    async def start(
        self,
        *,
        mode: ScanMode | None = None,
        log_dir: str | None = None,
        interface: str | None = None,
    ) -> dict:
        """Start a background scan (ingestion pipeline).

        This does NOT start Zeek. It validates the log directory exists and
        begins reading Zeek log files from it.

        Args:
            mode:      'file' or 'live'. Falls back to config.scan_mode or 'file'.
            log_dir:   Override log directory (both modes).
            interface: Informational only — records which interface Zeek is
                       capturing on (used for display in UI).

        Returns:
            Current status dict.

        Raises:
            RuntimeError: A scan is already running.
            ValueError:   Log directory does not exist.
        """
        async with self._lock:
            if self.running:
                raise RuntimeError("A scan is already running")

            # Resolve mode
            self._mode = mode or getattr(self._config, "scan_mode", "file")  # type: ignore[assignment]

            # Resolve log directory
            self._log_dir = log_dir or self._config.zeek_log_dir

            # Record interface (informational — we do NOT launch Zeek)
            self._interface = interface or getattr(self._config, "zeek_interface", None) or None

            # Validate log directory exists
            log_path = Path(self._log_dir)
            if not log_path.exists():
                raise ValueError(
                    f"Log directory does not exist: {self._log_dir}. "
                    "Ensure Zeek is running on the host and logs are mounted."
                )

            # Reset state
            self._cancel_event.clear()
            self._status = "running"
            self._error = None
            self._logs_processed = 0
            self._assets_discovered = 0
            self._started_at = datetime.now(timezone.utc)
            self._stopped_at = None
            self._job_id = str(uuid.uuid4())
            self._ingest_start_ts = time.monotonic()

            await self._persist_job_start(self._log_dir)

            # Dispatch to the correct pipeline
            if self._mode == "live":
                coro = self._run_live_pipeline()
            else:
                coro = self._run_file_pipeline(self._log_dir)

            self._task = asyncio.create_task(coro, name=f"scan-{self._job_id}")
            self._task.add_done_callback(self._on_task_done)

            logger.info(
                "Scan started",
                extra={
                    "job_id": self._job_id,
                    "mode": self._mode,
                    "log_dir": self._log_dir,
                },
            )
            return self.get_status()

    async def stop(self) -> dict:
        """Stop the running scan gracefully.

        Returns:
            Final status dict.
        """
        async with self._lock:
            if self._status in _TERMINAL_STATUSES:
                return self.get_status()
            if not self.running and self._task is None:
                return self.get_status()

            logger.info("Stopping scan", extra={"job_id": self._job_id, "mode": self._mode})

            # Signal cancellation
            self._cancel_event.set()

            # Cancel asyncio task
            if self._task and not self._task.done():
                self._task.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(self._task), timeout=10.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

            # Only mark stopped if not already terminal
            if self._status not in _TERMINAL_STATUSES:
                self._status = "stopped"
                self._stopped_at = datetime.now(timezone.utc)
                await self._persist_job_end("stopped")

            return self.get_status()

    async def restart(
        self,
        *,
        mode: ScanMode | None = None,
        log_dir: str | None = None,
        interface: str | None = None,
    ) -> dict:
        """Stop any running scan then start a new one with the given params."""
        await self.stop()
        return await self.start(
            mode=mode or self._mode,
            log_dir=log_dir or self._log_dir,
            interface=interface or self._interface,
        )

    def get_status(self) -> dict:
        """Return the current scan state as a serializable dict."""
        rate = 0.0
        if self._ingest_start_ts and self._logs_processed > 0:
            elapsed = time.monotonic() - self._ingest_start_ts
            rate = round(self._logs_processed / max(elapsed, 0.001), 1)

        return {
            "mode": self._mode,
            "status": self._status,
            "running": self.running,
            "job_id": self._job_id,
            "interface": self._interface,
            "log_dir": self._log_dir,
            "logs_processed": self._logs_processed,
            "assets_discovered": self._assets_discovered,
            "ingestion_rate": rate,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "stopped_at": self._stopped_at.isoformat() if self._stopped_at else None,
            "error": self._error,
        }

    # ── File-mode pipeline ─────────────────────────────────────────────────

    async def _run_file_pipeline(self, log_dir: str) -> None:
        """Read all Zeek log files from *log_dir* once, then complete."""
        try:
            before_count = await self._asset_count()
            await self._ingest_directory(Path(log_dir))

            if self._cancel_event.is_set():
                return

            await self._run_inference()

            after_count = await self._asset_count()
            self._assets_discovered = max(0, after_count - before_count)

            await self._generate_alerts()

            self._status = "completed"
            self._stopped_at = datetime.now(timezone.utc)
            await self._persist_job_end("completed")
            logger.info(
                "File scan completed",
                extra={
                    "job_id": self._job_id,
                    "logs_processed": self._logs_processed,
                    "assets_discovered": self._assets_discovered,
                },
            )

        except asyncio.CancelledError:
            self._status = "stopped"
            self._stopped_at = datetime.now(timezone.utc)
            await self._persist_job_end("stopped")
            raise

        except Exception as exc:
            self._status = "failed"
            self._error = str(exc)
            self._stopped_at = datetime.now(timezone.utc)
            await self._persist_job_end("failed", str(exc))
            logger.exception("File scan failed", extra={"job_id": self._job_id})

    # ── Live-mode pipeline ─────────────────────────────────────────────────

    async def _run_live_pipeline(self) -> None:
        """Continuously poll the Zeek log directory until stopped.

        This coroutine:
        1. Loads persisted file offsets from the DB.
        2. Loops every ``_LIVE_POLL_INTERVAL`` seconds, re-ingesting each
           log file from the saved offset to pick up new rows.
        3. Runs inference and alerting after each cycle.
        4. Detects log rotation (file shrinks → reset offset to 0).

        Zeek runs externally — this loop only reads its log files.
        """
        try:
            await self._live_ingest_loop(Path(self._log_dir))
        except asyncio.CancelledError:
            self._status = "stopped"
            self._stopped_at = datetime.now(timezone.utc)
            await self._persist_job_end("stopped")
            raise
        except Exception as exc:
            self._status = "failed"
            self._error = str(exc)
            self._stopped_at = datetime.now(timezone.utc)
            await self._persist_job_end("failed", str(exc))
            logger.exception("Live scan failed", extra={"job_id": self._job_id})

    async def _live_ingest_loop(self, log_dir: Path) -> None:
        """Poll Zeek log files at regular intervals and run the pipeline.

        Features:
        * **Persistent offsets** — byte offsets are loaded from the DB on
          startup and saved after every cycle so ingestion resumes exactly
          where it left off after a restart.
        * **Log rotation detection** — if a file shrinks (Zeek rotated it),
          the offset resets to 0 to re-read the new file from the start.
        * **Backpressure** — a semaphore ensures at most one ingest cycle
          runs concurrently.
        """
        file_offsets: dict[str, int] = await self._load_offsets_from_db(str(log_dir))
        cycle = 0

        while not self._cancel_event.is_set():
            # Backpressure: skip cycle if previous one is still running
            if not self._ingest_semaphore._value:  # noqa: SLF001
                logger.debug(
                    "Live ingest: previous cycle still in progress, skipping",
                    extra={"job_id": self._job_id},
                )
            else:
                async with self._ingest_semaphore:
                    # Detect log rotation: if file is smaller than offset, reset
                    for log_type, filename in LOG_FILE_MAP.items():
                        path = log_dir / filename
                        if path.exists():
                            current_size = path.stat().st_size
                            if current_size < file_offsets.get(log_type, 0):
                                logger.info(
                                    "Log rotation detected — resetting offset",
                                    extra={
                                        "log_type": log_type,
                                        "old_offset": file_offsets[log_type],
                                        "new_size": current_size,
                                    },
                                )
                                file_offsets[log_type] = 0

                    before_count = await self._asset_count()
                    await self._ingest_directory(log_dir, offsets=file_offsets)

                    # Advance offsets to current file sizes
                    for log_type, filename in LOG_FILE_MAP.items():
                        path = log_dir / filename
                        if path.exists():
                            file_offsets[log_type] = path.stat().st_size

                    # Persist offsets so a restart can resume here
                    await self._save_offsets_to_db(str(log_dir), file_offsets)

                    await self._run_inference()
                    after_count = await self._asset_count()
                    self._assets_discovered += max(0, after_count - before_count)
                    await self._generate_alerts()

                    cycle += 1
                    logger.debug(
                        "Live poll cycle complete",
                        extra={
                            "cycle": cycle,
                            "logs_processed": self._logs_processed,
                            "assets_total": after_count,
                        },
                    )

            # Wait for next poll interval or cancellation signal
            try:
                await asyncio.wait_for(
                    self._cancel_event.wait(),
                    timeout=_LIVE_POLL_INTERVAL,
                )
                break  # cancel event fired
            except asyncio.TimeoutError:
                pass  # normal — continue loop

        logger.info(
            "Live ingest loop ended",
            extra={"job_id": self._job_id, "cycles": cycle},
        )

    # ── File-offset persistence ────────────────────────────────────────────

    async def _load_offsets_from_db(self, log_dir: str) -> dict[str, int]:
        """Load previously saved byte offsets from the ``file_offsets`` table."""
        offsets: dict[str, int] = {t: 0 for t in ALL_TYPES}
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT log_type, byte_offset
                    FROM file_offsets
                    WHERE log_path = $1
                    """,
                    log_dir,
                )
                for row in rows:
                    lt = row["log_type"]
                    if lt in offsets:
                        offsets[lt] = row["byte_offset"]
            logger.debug(
                "Loaded file offsets from DB",
                extra={"log_dir": log_dir, "offsets": offsets},
            )
        except Exception:
            logger.exception("Could not load file offsets from DB — starting from 0")
        return offsets

    async def _save_offsets_to_db(self, log_dir: str, offsets: dict[str, int]) -> None:
        """Upsert the current byte offsets into the ``file_offsets`` table."""
        rows = [
            (log_type, log_dir, offset)
            for log_type, offset in offsets.items()
        ]
        try:
            async with self._pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO file_offsets (log_type, log_path, byte_offset, updated_at)
                    VALUES ($1, $2, $3, NOW())
                    ON CONFLICT (log_path, log_type)
                    DO UPDATE SET byte_offset = EXCLUDED.byte_offset,
                                  updated_at  = EXCLUDED.updated_at
                    """,
                    rows,
                )
        except Exception:
            logger.exception("Could not save file offsets to DB")

    # ── Shared helpers ─────────────────────────────────────────────────────

    async def _ingest_directory(
        self,
        target: Path,
        offsets: dict[str, int] | None = None,
    ) -> None:
        """Parse each supported Zeek log file found in *target*."""
        repo = Repository(self._pool)

        for log_type in ALL_TYPES:
            if self._cancel_event.is_set():
                return

            log_path = target / LOG_FILE_MAP[log_type]
            if not log_path.exists():
                continue

            parser_cls = PARSER_MAP[log_type]
            parser = parser_cls(repo, batch_size=self._config.batch_size)

            start_offset = offsets.get(log_type, 0) if offsets else 0
            result = await parser.ingest(log_path, start_offset=start_offset)
            self._logs_processed += result.get("rows_processed", 0)

    async def _run_inference(self) -> None:
        """Run the inference engine against current DB state."""
        if self._cancel_event.is_set():
            return
        await run_inference(
            pool=self._pool,
            dry_run=False,
            local_subnets=self._config.local_subnets_list,
        )

    async def _asset_count(self) -> int:
        async with self._pool.acquire() as conn:
            return await conn.fetchval("SELECT COUNT(*) FROM assets") or 0

    def _on_task_done(self, task: asyncio.Task) -> None:
        """Callback invoked when the background task exits."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            self._status = "failed"
            self._error = str(exc)

    # ------------------------------------------------------------------
    # Alert generation (runs after ingest + inference)
    # ------------------------------------------------------------------

    SUSPICIOUS_PORTS = {
        4444, 1337, 31337, 5555, 6666, 6667, 8888, 9999,
        4443, 1234, 7777, 12345, 54321,
    }

    async def _generate_alerts(self) -> None:
        """Generate alerts for suspicious patterns found during scan."""
        try:
            async with self._pool.acquire() as conn:
                # 1. New assets detected in last 5 minutes
                new_assets = await conn.fetch("""
                    SELECT a.id::text AS asset_id,
                           COALESCE(host(ai.ip_address)::text, 'unknown') AS ip,
                           a.mac_address
                    FROM assets a
                    LEFT JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
                    WHERE a.first_seen > NOW() - INTERVAL '5 minutes'
                """)

                alert_rows: list[tuple] = []

                for asset in new_assets:
                    ip = asset["ip"]
                    mac = asset["mac_address"] or "unknown"
                    alert_rows.append((
                        uuid.uuid4(),
                        "new_asset",
                        "medium",
                        f"New asset detected: {ip} (MAC: {mac})",
                        ip,
                        asset["asset_id"],
                    ))

                # 2. Unusual port usage
                suspicious = await conn.fetch("""
                    SELECT DISTINCT
                        b.asset_id::text AS asset_id,
                        b.port,
                        b.protocol,
                        b.service,
                        COALESCE(host(ai.ip_address)::text, 'unknown') AS ip
                    FROM behaviors b
                    JOIN asset_ips ai ON ai.asset_id = b.asset_id AND ai.is_primary = true
                    WHERE b.port = ANY($1::int[])
                      AND b.first_seen > NOW() - INTERVAL '10 minutes'
                """, list(self.SUSPICIOUS_PORTS))

                for row in suspicious:
                    alert_rows.append((
                        uuid.uuid4(),
                        "unusual_port",
                        "high",
                        f"Unusual port {row['port']}/{row['protocol']} detected on {row['ip']} "
                        f"(service: {row['service'] or 'unknown'})",
                        row["ip"],
                        row["asset_id"],
                    ))

                # 3. IoT/IoMT devices connecting to external IPs
                subnets = self._config.local_subnets_list
                external_conns = await conn.fetch("""
                    SELECT DISTINCT
                        c.src_asset_id::text AS asset_id,
                        host(c.src_ip)::text AS src_ip,
                        host(c.dst_ip)::text AS dst_ip,
                        c.dst_port,
                        ir.device_type
                    FROM connections c
                    JOIN inference_results ir ON ir.asset_id = c.src_asset_id
                    WHERE ir.device_type IN ('IoMT', 'IoT')
                      AND NOT (c.dst_ip <<= ANY($1::inet[]))
                      AND c.timestamp > NOW() - INTERVAL '10 minutes'
                    LIMIT 100
                """, subnets)

                for row in external_conns:
                    alert_rows.append((
                        uuid.uuid4(),
                        "external_connection",
                        "critical",
                        f"{row['device_type']} device {row['src_ip']} connecting to external IP "
                        f"{row['dst_ip']}:{row['dst_port']}",
                        row["src_ip"],
                        row["asset_id"],
                    ))

                if alert_rows:
                    await conn.executemany("""
                        INSERT INTO alerts (id, alert_type, severity, message,
                                            source_ip, asset_id, status,
                                            created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6::uuid, 'new', NOW(), NOW())
                        ON CONFLICT DO NOTHING
                    """, alert_rows)

                    logger.info(
                        "Alerts generated",
                        extra={"count": len(alert_rows), "job_id": self._job_id},
                    )

        except Exception:
            logger.exception("Alert generation failed")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _persist_job_start(self, log_dir: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO scan_jobs (id, status, log_dir, started_at, created_at)
                    VALUES ($1, 'running', $2, $3, $3)
                """, uuid.UUID(self._job_id), log_dir, self._started_at)
        except Exception:
            logger.exception("Failed to persist scan job start")

    async def _persist_job_end(self, status: str, error: str | None = None) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    UPDATE scan_jobs
                    SET status = $2,
                        stopped_at = $3,
                        logs_processed = $4,
                        assets_discovered = $5,
                        error_message = $6
                    WHERE id = $1
                """,
                    uuid.UUID(self._job_id),
                    status,
                    self._stopped_at,
                    self._logs_processed,
                    self._assets_discovered,
                    error,
                )
        except Exception:
            logger.exception("Failed to persist scan job end")
