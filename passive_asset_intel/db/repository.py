"""Repository — all database upsert/insert logic for the ingestion pipeline.

Every public method accepts a list of dicts (a batch) and writes them to
PostgreSQL using asyncpg.  All operations use UPSERT (ON CONFLICT … DO UPDATE)
where appropriate, and are wrapped in a single transaction per batch.

All VARCHAR / TEXT columns are explicitly cast via ``::text`` in the SQL
placeholders to avoid asyncpg "inconsistent types deduced for parameter"
errors when the same prepared statement is reused with None/str values.
"""

import asyncio
import uuid
from datetime import datetime
from typing import Any

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _uuid() -> str:
    return str(uuid.uuid4())


class Repository:
    """Encapsulates all write operations against the passive-asset-intel schema."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialize with an asyncpg connection pool.

        Args:
            pool: A live asyncpg pool obtained from ``Database.pool``.
        """
        self._pool = pool

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _execute_batch(
        self,
        query: str,
        rows: list[tuple],
        *,
        max_retries: int = 3,
    ) -> int:
        """Execute a batch statement inside a transaction with retry logic.

        Args:
            query: SQL statement with $1, $2, … placeholders.
            rows: List of tuples matching the placeholders.
            max_retries: Maximum retry attempts on transient DB errors.

        Returns:
            Number of rows successfully written.
        """
        for attempt in range(1, max_retries + 1):
            try:
                async with self._pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.executemany(query, rows)
                return len(rows)
            except (asyncpg.PostgresError, OSError) as exc:
                wait = 2**attempt
                logger.warning(
                    "Batch write failed, retrying",
                    extra={"attempt": attempt, "wait_seconds": wait, "error": str(exc)},
                )
                if attempt == max_retries:
                    raise
                await asyncio.sleep(wait)
        return 0  # unreachable, keeps mypy happy

    # ------------------------------------------------------------------
    # Asset resolution — ensures an asset row exists and returns its id
    # ------------------------------------------------------------------

    async def upsert_asset_by_mac(
        self,
        conn: asyncpg.Connection,
        mac: str,
        vendor: str | None,
        ts: datetime,
    ) -> str:
        """Upsert an asset identified by MAC address.

        Args:
            conn: Active asyncpg connection (inside a transaction).
            mac: MAC address string.
            vendor: Vendor / OUI string, may be None.
            ts: Timestamp of the observation.

        Returns:
            The UUID (as string) of the existing or newly-created asset.
        """
        row = await conn.fetchrow(
            """
            INSERT INTO assets (id, mac_address, vendor, first_seen, last_seen,
                                asset_status, confidence_score)
            VALUES ($1, $2::text, $3::text, $4, $4, 'active', 0.5)
            ON CONFLICT (mac_address) DO UPDATE
                SET last_seen       = GREATEST(assets.last_seen, EXCLUDED.last_seen),
                    vendor          = COALESCE(EXCLUDED.vendor, assets.vendor)
            RETURNING id
            """,
            uuid.uuid4(),
            mac,
            vendor,
            ts,
        )
        return str(row["id"])

    async def upsert_asset_by_ip(
        self,
        conn: asyncpg.Connection,
        ip: str,
        ts: datetime,
    ) -> str:
        """Upsert an asset identified only by IP (fallback when no MAC is available).

        We use a synthetic MAC ``ip:<addr>`` to guarantee uniqueness in the
        mac_address column.

        Args:
            conn: Active asyncpg connection.
            ip: IP address string.
            ts: Timestamp of the observation.

        Returns:
            The UUID (as string) of the asset.
        """
        synthetic_mac = f"ip:{ip}"
        row = await conn.fetchrow(
            """
            INSERT INTO assets (id, mac_address, first_seen, last_seen,
                                asset_status, confidence_score)
            VALUES ($1, $2::text, $3, $3, 'active', 0.3)
            ON CONFLICT (mac_address) DO UPDATE
                SET last_seen = GREATEST(assets.last_seen, EXCLUDED.last_seen)
            RETURNING id
            """,
            uuid.uuid4(),
            synthetic_mac,
            ts,
        )
        return str(row["id"])

    async def resolve_asset(
        self,
        conn: asyncpg.Connection,
        ip: str,
        ts: datetime,
        mac: str | None = None,
        vendor: str | None = None,
    ) -> str:
        """Resolve (or create) an asset, preferring MAC over IP.

        Args:
            conn: Active asyncpg connection.
            ip: IP address.
            ts: Observation timestamp.
            mac: Optional MAC address.
            vendor: Optional vendor string.

        Returns:
            Asset UUID as string.
        """
        if mac:
            asset_id = await self.upsert_asset_by_mac(conn, mac, vendor, ts)
        else:
            asset_id = await self.upsert_asset_by_ip(conn, ip, ts)
        return asset_id

    # ------------------------------------------------------------------
    # Asset IPs
    # ------------------------------------------------------------------

    async def upsert_asset_ip(
        self,
        conn: asyncpg.Connection,
        asset_id: str,
        ip: str,
        ts: datetime,
    ) -> None:
        """Link an IP address to an asset (upsert).

        Args:
            conn: Active asyncpg connection.
            asset_id: UUID of the parent asset.
            ip: IP address string.
            ts: Observation timestamp.
        """
        await conn.execute(
            """
            INSERT INTO asset_ips (id, asset_id, ip_address, first_seen, last_seen, is_primary)
            VALUES ($1, $2::uuid, $3::inet, $4, $4, true)
            ON CONFLICT (asset_id, ip_address)
                DO UPDATE SET last_seen = GREATEST(asset_ips.last_seen, EXCLUDED.last_seen)
            """,
            uuid.uuid4(),
            uuid.UUID(asset_id),
            ip,
            ts,
        )

    # ------------------------------------------------------------------
    # Batch writers — called from parsers
    # ------------------------------------------------------------------

    async def write_connections(self, rows: list[dict[str, Any]]) -> int:
        """Batch-insert connection records.

        Args:
            rows: List of dicts with keys matching the connections table.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["src_asset_id"]),
                uuid.UUID(r["dst_asset_id"]),
                r["src_ip"],
                r["dst_ip"],
                r["src_port"],
                r["dst_port"],
                r["protocol"],
                r.get("service"),
                r.get("duration"),
                r.get("bytes_sent"),
                r.get("bytes_received"),
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO connections
                (id, src_asset_id, dst_asset_id, src_ip, dst_ip, src_port,
                 dst_port, protocol, service, duration, bytes_sent, bytes_received, timestamp)
            VALUES ($1, $2, $3, $4::inet, $5::inet, $6, $7,
                    $8::text, $9::text, $10, $11, $12, $13)
            ON CONFLICT DO NOTHING
            """,
            tuples,
        )

    async def write_behaviors(self, rows: list[dict[str, Any]]) -> int:
        """Batch-upsert behavior records (frequency increments).

        Args:
            rows: List of dicts with asset_id, protocol, port, service, timestamp.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r["protocol"] or "",
                r.get("port") or 0,
                r.get("service") or "",
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO behaviors (id, asset_id, protocol, port, service,
                                   frequency, first_seen, last_seen)
            VALUES ($1, $2, $3::text, $4, $5::text, 1, $6, $6)
            ON CONFLICT (asset_id, protocol, port, service)
                DO UPDATE SET frequency  = behaviors.frequency + 1,
                              last_seen  = GREATEST(behaviors.last_seen, EXCLUDED.last_seen)
            """,
            tuples,
        )

    async def write_dns_queries(self, rows: list[dict[str, Any]]) -> int:
        """Batch-insert DNS query records.

        Args:
            rows: List of dicts with asset_id, query, answer, query_type, timestamp.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r["query"],
                r.get("answer"),
                r.get("query_type"),
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO dns_queries (id, asset_id, query, answer, query_type, timestamp)
            VALUES ($1, $2, $3::text, $4::text, $5::text, $6)
            ON CONFLICT DO NOTHING
            """,
            tuples,
        )

    async def write_http_sessions(self, rows: list[dict[str, Any]]) -> int:
        """Batch-insert HTTP session records.

        Args:
            rows: List of dicts matching the http_sessions table.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r.get("host"),
                r.get("uri"),
                r.get("user_agent"),
                r.get("method"),
                r.get("status_code"),
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO http_sessions
                (id, asset_id, host, uri, user_agent, method, status_code, timestamp)
            VALUES ($1, $2, $3::text, $4::text, $5::text,
                    $6::text, $7::int, $8)
            ON CONFLICT DO NOTHING
            """,
            tuples,
        )

    async def write_tls_sessions(self, rows: list[dict[str, Any]]) -> int:
        """Batch-insert TLS session records.

        Args:
            rows: List of dicts matching the tls_sessions table.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r.get("ja3"),
                r.get("ja3s"),
                r.get("server_name"),
                r.get("certificate_issuer"),
                r.get("version"),
                r.get("next_protocol"),
                r.get("validation_status"),
                r.get("sni_matches_cert"),
                r.get("ssl_history"),
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO tls_sessions
                (
                    id, asset_id, ja3, ja3s, server_name, certificate_issuer,
                    version, next_protocol, validation_status, sni_matches_cert,
                    ssl_history, timestamp
                )
            VALUES ($1, $2, $3::text, $4::text, $5::text,
                    $6::text, $7::text, $8::text, $9::text, $10::boolean,
                    $11::text, $12)
            ON CONFLICT DO NOTHING
            """,
            tuples,
        )

    async def write_fingerprints(self, rows: list[dict[str, Any]]) -> int:
        """Batch-upsert fingerprint records.

        Uses the expression-based unique index ``uq_fingerprints_composite``
        which COALESCEs NULLs to empty strings.

        Args:
            rows: List of dicts with asset_id and one or more of ja3, ja3s,
                  user_agent, dhcp_vendor, plus timestamp.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r.get("ja3"),
                r.get("ja3s"),
                r.get("user_agent"),
                r.get("dhcp_vendor"),
                r["timestamp"],
            )
            for r in rows
        ]
        # Expression index uses COALESCE, so ON CONFLICT on plain columns
        # won't match.  We use INSERT ... WHERE NOT EXISTS fallback.
        return await self._execute_batch(
            """
            INSERT INTO fingerprints
                (id, asset_id, ja3, ja3s, user_agent, dhcp_vendor, first_seen, last_seen)
            SELECT $1, $2, $3::text, $4::text, $5::text, $6::text, $7, $7
            WHERE NOT EXISTS (
                SELECT 1 FROM fingerprints
                WHERE asset_id = $2
                  AND COALESCE(ja3, '')         = COALESCE($3::text, '')
                  AND COALESCE(ja3s, '')        = COALESCE($4::text, '')
                  AND COALESCE(user_agent, '')  = COALESCE($5::text, '')
                  AND COALESCE(dhcp_vendor, '') = COALESCE($6::text, '')
            )
            """,
            tuples,
        )

    async def write_asset_hostnames(self, rows: list[dict[str, Any]]) -> int:
        """Batch-upsert asset hostname records.

        Args:
            rows: List of dicts with asset_id, hostname, source, timestamp.

        Returns:
            Number of rows written.
        """
        if not rows:
            return 0
        tuples = [
            (
                uuid.uuid4(),
                uuid.UUID(r["asset_id"]),
                r["hostname"],
                r.get("source", "dhcp"),
                r["timestamp"],
            )
            for r in rows
        ]
        return await self._execute_batch(
            """
            INSERT INTO asset_hostnames (id, asset_id, hostname, source, first_seen, last_seen)
            VALUES ($1, $2, $3::text, $4::text, $5, $5)
            ON CONFLICT (asset_id, hostname)
                DO UPDATE SET last_seen = GREATEST(asset_hostnames.last_seen, EXCLUDED.last_seen)
            """,
            tuples,
        )
