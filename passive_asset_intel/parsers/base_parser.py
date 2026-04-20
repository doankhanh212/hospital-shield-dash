"""Abstract base class for all Zeek log parsers — supports TSV (default) and JSON formats."""

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.utils.logger import setup_logger


class BaseParser(ABC):
    """Base class providing streaming TSV read, batching, and error handling.

    Zeek 8.x writes logs in tab-separated format by default with a header
    block starting with ``#``.  The ``#fields`` line defines column names;
    the ``#types`` line defines types.  Data rows follow immediately after.

    Subclasses must implement :meth:`process_batch`.
    """

    LOG_FILE: str = ""

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        self.repo = repo
        self.batch_size = batch_size
        self.logger = setup_logger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Timestamp helper
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ts(raw: Any) -> datetime:
        """Convert a Zeek epoch timestamp to a naive UTC datetime.

        Returns a timezone-naive datetime because the PostgreSQL schema uses
        ``timestamp`` (without time zone).  asyncpg cannot bind a tz-aware
        datetime to a ``timestamp`` column.
        """
        try:
            return datetime.utcfromtimestamp(float(raw))
        except (TypeError, ValueError, OverflowError):
            return datetime.utcnow()

    # ------------------------------------------------------------------
    # TSV streaming reader
    # ------------------------------------------------------------------

    async def _stream_lines(
        self,
        path: Path,
        start_offset: int = 0,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield dicts from a Zeek TSV log file.

        Parses the ``#fields`` header to build column names, then maps each
        data row to a dict.  Lines starting with ``#`` (metadata/comments)
        and empty lines are skipped.  Malformed rows are logged and skipped.

        When *start_offset* > 0 (live-mode incremental reads):
        - On the **first read** (offset 0) the header is parsed normally.
        - On **subsequent reads** the file is seeked to *start_offset* and
          the first (potentially partial) line is discarded to avoid
          ingesting a truncated row.  The ``#fields`` header from the
          previous read is reused.

        Args:
            path:          Path to the Zeek .log file.
            start_offset:  Byte offset to resume reading from.

        Yields:
            Dict mapping field name → raw string value for each data row.
        """
        fields: list[str] = []
        unset_value = "-"
        empty_value = "(empty)"

        loop = asyncio.get_running_loop()

        def _read_lines() -> list[str]:
            """Read file lines from disk (runs in thread to avoid blocking)."""
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if start_offset > 0:
                    fh.seek(start_offset)
                    # Discard partial line at the seek point
                    fh.readline()
                return fh.readlines()

        raw_lines = await loop.run_in_executor(None, _read_lines)

        for line_no, raw_line in enumerate(raw_lines, start=1):
            line = raw_line.rstrip("\n")
            if line.startswith("#fields"):
                # Tab-separated after the directive
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#unset_field"):
                unset_value = line.split("\t")[1] if "\t" in line else "-"
                continue
            if line.startswith("#empty_field"):
                empty_value = line.split("\t")[1] if "\t" in line else "(empty)"
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields:
                # In incremental mode, we may not see #fields again.
                # Re-read the header from the beginning of the file.
                if start_offset > 0:
                    fields = await self._read_header_fields(path, loop)
                if not fields:
                    self.logger.warning(
                        "Data row before #fields header",
                        extra={"file": str(path), "line": line_no},
                    )
                    continue
            parts = line.split("\t")
            if len(parts) != len(fields):
                self.logger.warning(
                    "Column count mismatch, skipping row",
                    extra={
                        "file": str(path),
                        "line": line_no,
                        "expected": len(fields),
                        "got": len(parts),
                    },
                )
                continue
            try:
                record: dict[str, Any] = {}
                for key, val in zip(fields, parts):
                    if val == unset_value or val == empty_value:
                        record[key] = None
                    else:
                        record[key] = val
                yield record
            except Exception as exc:
                self.logger.warning(
                    "Failed to parse row",
                    extra={"file": str(path), "line": line_no, "error": str(exc)},
                )

    @staticmethod
    async def _read_header_fields(path: Path, loop) -> list[str]:
        """Read only the #fields line from the top of a Zeek log file."""
        def _read():
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    if raw.startswith("#fields"):
                        return raw.rstrip("\n").split("\t")[1:]
                    if not raw.startswith("#"):
                        break
            return []
        return await loop.run_in_executor(None, _read)

    # ------------------------------------------------------------------
    # Batch orchestration
    # ------------------------------------------------------------------

    async def ingest(
        self,
        path: Path,
        start_offset: int = 0,
    ) -> dict[str, int]:
        """Stream a Zeek log file and process in batches.

        Args:
            path:          Path to the log file.
            start_offset:  Byte offset to resume reading from (live mode).

        Returns:
            Dict with ``rows_processed`` and ``rows_failed``.
        """
        self.logger.info(
            "Starting ingestion",
            extra={"file": str(path), "offset": start_offset},
        )
        batch: list[dict[str, Any]] = []
        total_processed = 0
        total_failed = 0

        async for record in self._stream_lines(path, start_offset=start_offset):
            batch.append(record)
            if len(batch) >= self.batch_size:
                p, f = await self._flush(batch)
                total_processed += p
                total_failed += f
                batch = []

        if batch:
            p, f = await self._flush(batch)
            total_processed += p
            total_failed += f

        self.logger.info(
            "Ingestion complete",
            extra={
                "file": str(path),
                "rows_processed": total_processed,
                "rows_failed": total_failed,
            },
        )
        return {"rows_processed": total_processed, "rows_failed": total_failed}

    async def _flush(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process one batch, catching and logging top-level errors."""
        start = time.monotonic()
        try:
            processed, failed = await self.process_batch(batch)
            elapsed = time.monotonic() - start
            self.logger.info(
                "Batch written",
                extra={
                    "rows_processed": processed,
                    "rows_failed": failed,
                    "batch_duration": round(elapsed, 4),
                },
            )
            return processed, failed
        except Exception:
            elapsed = time.monotonic() - start
            self.logger.exception(
                "Batch failed",
                extra={"batch_size": len(batch), "batch_duration": round(elapsed, 4)},
            )
            return 0, len(batch)

    @abstractmethod
    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of parsed Zeek rows.

        Args:
            batch: List of dicts (field→value) from the TSV parser.

        Returns:
            Tuple of (rows_processed, rows_failed).
        """
        ...
