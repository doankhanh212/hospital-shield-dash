"""Inference engine orchestrator.

Fetches all assets with their behaviors and fingerprints in a single query,
runs MAC vendor lookup and device classification for each, and writes results
back to the database.

Usage::

    await run_inference(dsn="postgresql://user:pass@host/db")
    await run_inference(pool=existing_pool)  # preferred — no pool churn
"""

from __future__ import annotations

import json
from typing import Any, Sequence

import asyncpg

from passive_asset_intel.inference.categorizer import categorize_features
from passive_asset_intel.inference.device_classifier import classify_asset
from passive_asset_intel.inference.identity import find_and_merge_duplicates
from passive_asset_intel.inference.mac_vendor import MacVendorResolver
from passive_asset_intel.inference.validators import is_real_mac
from passive_asset_intel.inference.writer import ensure_unique_constraint, upsert_inference
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

# Default fallback — RFC1918 private address space.  Callers should pass in
# the list from Config.local_subnets_list so deployments on public VPS ranges
# (e.g. 103.98.152.0/24) also get classified.
DEFAULT_LOCAL_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

FETCH_ASSETS_SQL = """
SELECT
    a.id::text                   AS id,
    a.mac_address,
    a.vendor,
    COALESCE(
        (SELECT json_agg(json_build_object(
            'ja3', f.ja3,
            'ja3s', f.ja3s,
            'user_agent', f.user_agent,
            'dhcp_vendor', f.dhcp_vendor
        ))
        FROM fingerprints f WHERE f.asset_id = a.id),
        '[]'::json
    ) AS fingerprints,
    COALESCE(
        (SELECT json_agg(q.hn) FROM (
            SELECT DISTINCT ah.hostname AS hn
            FROM asset_hostnames ah
            WHERE ah.asset_id = a.id
            LIMIT 20
        ) q),
        '[]'::json
    ) AS hostnames,
    COALESCE(
        (SELECT json_agg(q.domain) FROM (
            SELECT DISTINCT dq.query AS domain
            FROM dns_queries dq
            WHERE dq.asset_id = a.id
              AND dq.query IS NOT NULL
              AND dq.query <> ''
            LIMIT 300
        ) q),
        '[]'::json
    ) AS dns_queries,
    COALESCE(
        (SELECT json_agg(q.sni) FROM (
            SELECT DISTINCT ts.server_name AS sni
            FROM tls_sessions ts
            WHERE ts.asset_id = a.id
              AND ts.server_name IS NOT NULL
            LIMIT 100
        ) q),
        '[]'::json
    ) AS ssl_sni,
    COALESCE(
        (SELECT json_agg(q.host) FROM (
            SELECT DISTINCT hs.host AS host
            FROM http_sessions hs
            WHERE hs.asset_id = a.id
              AND hs.host IS NOT NULL
              AND hs.host <> ''
            LIMIT 200
        ) q),
        '[]'::json
    ) AS http_hosts,
    -- Ports this asset *reached out to* (asset was id.orig_h).
    -- These are signals about what kind of CLIENT the asset is.
    COALESCE(
        (SELECT json_agg(q.port) FROM (
            SELECT DISTINCT c.dst_port AS port
            FROM connections c
            WHERE c.src_asset_id = a.id
              AND c.dst_port IS NOT NULL
              AND c.dst_port > 0
        ) q),
        '[]'::json
    ) AS client_dst_ports,
    -- Ports other hosts reached out to *on this asset* (asset was id.resp_h).
    -- These are signals about what kind of SERVER the asset is.
    COALESCE(
        (SELECT json_agg(q.port) FROM (
            SELECT DISTINCT c.dst_port AS port
            FROM connections c
            WHERE c.dst_asset_id = a.id
              AND c.dst_port IS NOT NULL
              AND c.dst_port > 0
        ) q),
        '[]'::json
    ) AS server_listen_ports
FROM assets a
WHERE a.asset_status = 'active'
  AND EXISTS (
    SELECT 1
    FROM asset_ips ai
    WHERE ai.asset_id = a.id
      AND ai.ip_address <<= ANY($1::inet[])
)
ORDER BY a.id
"""


# ────────────────────────────────────────────────────────────────────────
# Feature Builder — normalised feature dict per asset row
# ────────────────────────────────────────────────────────────────────────


def _json_list(val: object) -> list:
    """Parse a JSON column to a list, dropping None entries."""
    if isinstance(val, str):
        parsed = json.loads(val)
    else:
        parsed = val
    return [x for x in (parsed or []) if x is not None]


def _port_set(val: object) -> set[int]:
    """Parse a JSON column to a set of valid port numbers."""
    out: set[int] = set()
    for p in _json_list(val):
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if n > 0:
            out.add(n)
    return out


def build_features(row: Any, vendor: str | None) -> dict:
    """Build a normalised feature dict from a database row.

    Extracts and structures all signal sources (fingerprints, ports,
    hostnames, DNS, TLS, HTTP) into the shape that ``classify_asset()``
    expects, then enriches with categorized features (port service groups,
    DNS categories, JA3 categories) via the categorizer layer.

    Args:
        row: An asyncpg Record from FETCH_ASSETS_SQL.
        vendor: Resolved vendor string (may come from MAC OUI lookup).

    Returns:
        Feature dict ready for ``classify_asset()``.
    """
    fingerprints = (
        json.loads(row["fingerprints"])
        if isinstance(row["fingerprints"], str)
        else row["fingerprints"]
    )

    # Extract JA3/JA3S hashes from fingerprints so categorizer can map them.
    client_ja3: set[str] = set()
    server_ja3s: set[str] = set()
    for fp in fingerprints or []:
        if isinstance(fp, dict):
            if fp.get("ja3"):
                client_ja3.add(fp["ja3"])
            if fp.get("ja3s"):
                server_ja3s.add(fp["ja3s"])

    raw = {
        "mac_address": row["mac_address"],
        "vendor": vendor,
        "fingerprints": fingerprints,
        "client_dst_ports": _port_set(row["client_dst_ports"]),
        "server_listen_ports": _port_set(row["server_listen_ports"]),
        "client_ja3": client_ja3,
        "server_ja3s": server_ja3s,
        "hostnames": _json_list(row["hostnames"]),
        "dns_queries": _json_list(row["dns_queries"]),
        "ssl_sni": _json_list(row["ssl_sni"]),
        "http_hosts": _json_list(row["http_hosts"]),
    }

    return categorize_features(raw)


async def run_inference(
    dsn: str | None = None,
    dry_run: bool = False,
    local_subnets: Sequence[str] | None = None,
    *,
    pool: asyncpg.Pool | None = None,
) -> dict:
    """Run the full inference pipeline across all assets.

    1. Fetch all assets with aggregated behaviors and fingerprints.
    2. Look up MAC vendor for assets without a known vendor.
    3. Classify each asset using all available signals.
    4. Write (or print in dry-run mode) results.

    Args:
        dsn: PostgreSQL connection string. Ignored when *pool* is given.
        dry_run: If True, print results as JSON instead of writing to DB.
        local_subnets: CIDRs considered "local" — only assets whose primary IP
            falls in one of these subnets are classified.
        pool: An existing asyncpg pool to reuse (preferred — avoids creating
            a throwaway pool on every call).

    Returns:
        Summary dict with counts per device type.
    """
    subnets = list(local_subnets) if local_subnets else list(DEFAULT_LOCAL_SUBNETS)

    # Reuse provided pool or create a temporary one
    owns_pool = pool is None
    if owns_pool:
        if not dsn:
            raise ValueError("Either dsn or pool must be provided")
        pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, statement_cache_size=0)

    resolver = MacVendorResolver()

    try:
        if not dry_run:
            await ensure_unique_constraint(pool)

        async with pool.acquire() as conn:
            rows = await conn.fetch(FETCH_ASSETS_SQL, subnets)

        logger.info(
            "Fetched assets for inference",
            extra={"count": len(rows), "subnets": subnets},
        )

        counters: dict[str, int] = {}
        results_table: list[dict] = []
        skipped = 0

        # ── Identity resolution: merge IP-only duplicates ────────
        # Run before classification so merged assets get a single,
        # richer feature set instead of multiple weak ones.
        if not dry_run:
            merge_count = await find_and_merge_duplicates(pool, rows)
            if merge_count > 0:
                logger.info(
                    "Identity engine merged duplicate assets",
                    extra={"merged": merge_count},
                )
                # Re-fetch after merges so we classify the canonical assets
                async with pool.acquire() as conn:
                    rows = await conn.fetch(FETCH_ASSETS_SQL, subnets)
                logger.info(
                    "Re-fetched assets after identity merge",
                    extra={"count": len(rows)},
                )

        for row in rows:
            asset_id = row["id"]
            mac = row["mac_address"]
            vendor = row["vendor"]

            try:
                if (not vendor or vendor == "Unknown") and is_real_mac(mac):
                    vendor = await resolver.lookup(mac)

                asset_data = build_features(row, vendor)
                result = classify_asset(asset_data)

                dt = result["device_type"]
                counters[dt] = counters.get(dt, 0) + 1

                if dry_run:
                    results_table.append({
                        "asset_id": asset_id,
                        "mac": mac,
                        "device_type": result["device_type"],
                        "os": result["os"],
                        "vendor": result["vendor"],
                        "confidence": result["confidence"],
                        "method": result["method"],
                    })
                else:
                    await upsert_inference(pool, asset_id, result)

            except Exception:
                skipped += 1
                logger.exception(
                    "Inference failed for asset, skipping",
                    extra={"asset_id": asset_id, "mac": mac},
                )

        total = len(rows)
        iomt = counters.get("IoMT", 0)
        iot = counters.get("IoT", 0)
        network = counters.get("Network", 0)
        workstation = counters.get("Workstation", 0)
        unknown = counters.get("Unknown", 0)
        classified = sum(counters.values())

        # Full-coverage invariant: every fetched asset must either have a
        # row written (classified) or be counted as skipped. The sum must
        # equal total. If it doesn't, a code path lost an asset silently.
        if classified + skipped != total:
            logger.error(
                "Coverage invariant violated",
                extra={
                    "total": total,
                    "classified": classified,
                    "skipped": skipped,
                    "delta": total - classified - skipped,
                },
            )

        logger.info(
            "Inference complete: %d assets processed, "
            "%d IoMT, %d IoT, %d Network, %d Workstation, %d Unknown, %d skipped",
            total, iomt, iot, network, workstation, unknown, skipped,
        )

        if dry_run:
            print(json.dumps(results_table, indent=2))

        return {
            "total": total,
            "IoMT": iomt,
            "IoT": iot,
            "Network": network,
            "Workstation": workstation,
            "Unknown": unknown,
            "skipped": skipped,
        }

    finally:
        await resolver.close()
        if owns_pool:
            await pool.close()
