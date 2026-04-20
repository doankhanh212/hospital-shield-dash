"""CLI entry point for the Passive Asset Intelligence ingestion pipeline.

Usage examples::

    # Ingest all log types from the default ZEEK_LOG_DIR
    python -m passive_asset_intel ingest

    # Ingest only conn and dns logs from a custom directory
    python -m passive_asset_intel ingest --log-dir /data/zeek/2024-01-15 --types conn dns

    # Custom batch size and env file
    python -m passive_asset_intel ingest --env /etc/pai/.env --batch-size 1000

    # Ingest a single file directly
    python -m passive_asset_intel ingest --file /data/zeek/conn.log --types conn

    # Run inference on all assets
    python -m passive_asset_intel infer

    # Dry run — print results, no DB writes
    python -m passive_asset_intel infer --dry-run

    # Run ingestion then inference in sequence
    python -m passive_asset_intel run-all
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path

from passive_asset_intel.db.db import Database
from passive_asset_intel.db.repository import Repository
from passive_asset_intel.inference.engine import run_inference
from passive_asset_intel.parsers.conn_parser import ConnParser
from passive_asset_intel.parsers.dhcp_parser import DhcpParser
from passive_asset_intel.parsers.dns_parser import DnsParser
from passive_asset_intel.parsers.http_parser import HttpParser
from passive_asset_intel.parsers.ssl_parser import SslParser
from passive_asset_intel.utils.config import load_config
from passive_asset_intel.utils.logger import setup_logger

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


def _build_dsn(config) -> str:
    """Build a PostgreSQL DSN string from a Config object.

    Args:
        config: Application Config dataclass.

    Returns:
        PostgreSQL connection string.
    """
    return (
        f"postgresql://{config.db_user}:{config.db_password}"
        f"@{config.db_host}:{config.db_port}/{config.db_name}"
    )


def build_argparser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser with subcommands.

    Returns:
        Configured argparse.ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="passive_asset_intel",
        description="Passive Asset Intelligence — ingest Zeek logs and classify hospital assets.",
    )
    parser.add_argument(
        "--env",
        type=str,
        default=None,
        help="Path to .env file (default: auto-detect)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── ingest subcommand ─────────────────────────────────────────────
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest Zeek JSON logs into PostgreSQL.",
    )
    ingest_parser.add_argument(
        "--log-dir",
        type=str,
        default=None,
        help="Directory containing Zeek JSON log files (overrides ZEEK_LOG_DIR from .env)",
    )
    ingest_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Path to a single Zeek log file to ingest (use with --types to specify log type)",
    )
    ingest_parser.add_argument(
        "--types",
        nargs="+",
        choices=ALL_TYPES,
        default=None,
        help="Log types to process (default: all). Order: dhcp first for MAC resolution.",
    )
    ingest_parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Override BATCH_SIZE from .env",
    )

    # ── infer subcommand ──────────────────────────────────────────────
    infer_parser = subparsers.add_parser(
        "infer",
        help="Run device classification inference on all assets.",
    )
    infer_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print results as JSON table instead of writing to DB.",
    )

    # ── run-all subcommand ────────────────────────────────────────────
    run_all_parser = subparsers.add_parser(
        "run-all",
        help="Run ingestion then inference in sequence.",
    )
    run_all_parser.add_argument(
        "--log-dir",
        type=str,
        default=None,
        help="Directory containing Zeek JSON log files (overrides ZEEK_LOG_DIR from .env)",
    )
    run_all_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Path to a single Zeek log file to ingest (use with --types to specify log type)",
    )
    run_all_parser.add_argument(
        "--types",
        nargs="+",
        choices=ALL_TYPES,
        default=None,
        help="Log types to process (default: all).",
    )
    run_all_parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Override BATCH_SIZE from .env",
    )
    run_all_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print inference results as JSON table instead of writing to DB.",
    )

    return parser


async def run_ingest(args: argparse.Namespace, config) -> None:
    """Execute the ingestion pipeline.

    Args:
        args: Parsed CLI arguments.
        config: Application Config.
    """
    logger = setup_logger("main", config.log_level)

    batch_size = args.batch_size or config.batch_size
    log_types = list(args.types) if args.types else list(ALL_TYPES)
    log_dir = Path(args.log_dir) if args.log_dir else Path(config.zeek_log_dir)

    logger.info(
        "Pipeline starting",
        extra={
            "log_dir": str(log_dir),
            "types": log_types,
            "batch_size": batch_size,
        },
    )

    db = Database(config)
    await db.connect()

    try:
        repo = Repository(db.pool)
        grand_total = {"rows_processed": 0, "rows_failed": 0}
        pipeline_start = time.monotonic()

        for log_type in log_types:
            parser_cls = PARSER_MAP[log_type]
            parser = parser_cls(repo, batch_size=batch_size)

            if args.file:
                log_path = Path(args.file)
            else:
                log_path = log_dir / LOG_FILE_MAP[log_type]

            if not log_path.exists():
                logger.warning("Log file not found, skipping", extra={"file": str(log_path)})
                continue

            result = await parser.ingest(log_path)
            grand_total["rows_processed"] += result["rows_processed"]
            grand_total["rows_failed"] += result["rows_failed"]

        elapsed = round(time.monotonic() - pipeline_start, 2)
        logger.info(
            "Pipeline complete",
            extra={
                "total_processed": grand_total["rows_processed"],
                "total_failed": grand_total["rows_failed"],
                "duration_seconds": elapsed,
            },
        )
    finally:
        await db.disconnect()


async def run_infer(args: argparse.Namespace, config) -> None:
    """Execute the inference pipeline.

    Args:
        args: Parsed CLI arguments.
        config: Application Config.
    """
    logger = setup_logger("main", config.log_level)
    dsn = _build_dsn(config)
    dry_run = getattr(args, "dry_run", False)

    local_subnets = config.local_subnets_list
    logger.info(
        "Starting inference",
        extra={"dry_run": dry_run, "local_subnets": local_subnets},
    )
    await run_inference(dsn, dry_run=dry_run, local_subnets=local_subnets)


async def run_all(args: argparse.Namespace, config) -> None:
    """Execute ingestion followed by inference.

    Args:
        args: Parsed CLI arguments.
        config: Application Config.
    """
    await run_ingest(args, config)
    await run_infer(args, config)


def main() -> None:
    """CLI entry point — parse arguments and run the appropriate command."""
    parser = build_argparser()
    args = parser.parse_args()
    config = load_config(args.env)

    if args.command is None:
        # Backwards-compat: no subcommand → run ingest with legacy args
        parser.print_help()
        sys.exit(1)

    if args.command == "ingest":
        asyncio.run(run_ingest(args, config))
    elif args.command == "infer":
        asyncio.run(run_infer(args, config))
    elif args.command == "run-all":
        asyncio.run(run_all(args, config))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
