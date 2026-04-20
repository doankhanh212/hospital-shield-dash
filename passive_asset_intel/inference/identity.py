"""Identity Engine — detect and merge duplicate assets.

IP-only assets (``mac_address = 'ip:<addr>'``) are created when no L2 MAC is
visible.  The identity engine merges IP-only assets into MAC-based assets
when there is concrete evidence of identity overlap:

1.  **IP overlap** — the IP-only asset shares an IP with a MAC-based asset.
2.  **Hostname match** — the IP-only asset shares a hostname with a
    MAC-based asset (e.g. DHCP-assigned name).

Merge rules
-----------
*   MAC-based assets are ALWAYS canonical — never merged away.
*   IP-only ↔ IP-only merges are FORBIDDEN (too ambiguous).
*   Soft-delete: merged assets get ``asset_status = 'merged'`` and
    ``merged_into = <canonical_id>`` instead of being hard-deleted.
*   Every merge is recorded in the ``merge_history`` table.
*   Maximum 10 merges per cycle to prevent cascade errors.

Behavioural fingerprints (JA3, DNS, User-Agent) are NOT used for identity
because they identify software stacks, not physical devices.

Usage::

    merged_count = await find_and_merge_duplicates(pool, asset_rows)
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Sequence

import asyncpg

from passive_asset_intel.inference.validators import is_real_mac
from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

# Maximum merges per inference cycle.  Prevents runaway cascades.
_MAX_MERGES_PER_CYCLE = 10


async def _find_merge_target(
    pool: asyncpg.Pool,
    ip_asset_id: uuid.UUID,
) -> tuple[uuid.UUID | None, str, dict]:
    """Find a MAC-based asset to merge this IP-only asset into.

    Strategy 1: IP address overlap (strongest signal).
    Strategy 2: Hostname match (DHCP-assigned names).

    Returns:
        (canonical_uuid, reason_string, evidence_dict) or (None, "", {}).
    """
    async with pool.acquire() as conn:
        # Strategy 1: shared IP address
        row = await conn.fetchrow(
            """
            SELECT ai_mac.asset_id, a_mac.mac_address,
                   ai_ip.ip_address::text AS shared_ip
            FROM asset_ips ai_ip
            JOIN asset_ips ai_mac ON ai_ip.ip_address = ai_mac.ip_address
            JOIN assets a_mac ON ai_mac.asset_id = a_mac.id
            WHERE ai_ip.asset_id = $1
              AND a_mac.id != $1
              AND a_mac.mac_address NOT LIKE 'ip:%'
              AND a_mac.asset_status = 'active'
            ORDER BY a_mac.last_seen DESC
            LIMIT 1
            """,
            ip_asset_id,
        )
        if row is not None:
            return (
                row["asset_id"],
                "ip_overlap",
                {"shared_ip": row["shared_ip"], "canonical_mac": row["mac_address"]},
            )

        # Strategy 2: shared hostname
        row = await conn.fetchrow(
            """
            SELECT ah_mac.asset_id, a_mac.mac_address,
                   ah_ip.hostname AS shared_hostname
            FROM asset_hostnames ah_ip
            JOIN asset_hostnames ah_mac
                ON LOWER(ah_ip.hostname) = LOWER(ah_mac.hostname)
            JOIN assets a_mac ON ah_mac.asset_id = a_mac.id
            WHERE ah_ip.asset_id = $1
              AND a_mac.id != $1
              AND a_mac.mac_address NOT LIKE 'ip:%'
              AND a_mac.asset_status = 'active'
            ORDER BY a_mac.last_seen DESC
            LIMIT 1
            """,
            ip_asset_id,
        )
        if row is not None:
            return (
                row["asset_id"],
                "hostname_match",
                {"shared_hostname": row["shared_hostname"], "canonical_mac": row["mac_address"]},
            )

    return None, "", {}


async def find_and_merge_duplicates(
    pool: asyncpg.Pool,
    rows: Sequence[Any],
) -> int:
    """Identify and merge duplicate assets using identity overlap.

    Only IP-only assets can be merged INTO MAC-based assets.
    IP-only ↔ IP-only merges are forbidden.

    Args:
        pool: asyncpg connection pool.
        rows: Asset rows from FETCH_ASSETS_SQL.

    Returns:
        Number of assets merged.
    """
    ip_only_assets = [r for r in rows if not is_real_mac(r["mac_address"])]
    has_mac_targets = any(is_real_mac(r["mac_address"]) for r in rows)

    if not ip_only_assets or not has_mac_targets:
        return 0

    merged = 0
    for ip_asset in ip_only_assets:
        if merged >= _MAX_MERGES_PER_CYCLE:
            logger.warning(
                "Merge cap reached, deferring remaining merges",
                extra={"cap": _MAX_MERGES_PER_CYCLE},
            )
            break

        ip_asset_id = uuid.UUID(ip_asset["id"])

        canonical_id, reason, evidence = await _find_merge_target(
            pool, ip_asset_id,
        )
        if canonical_id is None:
            continue

        try:
            await _merge_asset_soft(
                pool, canonical_id, ip_asset_id, reason, evidence,
            )
            merged += 1
            logger.info(
                "Merged IP-only asset into MAC-based asset",
                extra={
                    "canonical_id": str(canonical_id),
                    "merged_id": str(ip_asset_id),
                    "merged_mac": ip_asset["mac_address"],
                    "reason": reason,
                },
            )
        except Exception:
            logger.exception(
                "Failed to merge asset",
                extra={
                    "canonical_id": str(canonical_id),
                    "merged_id": str(ip_asset_id),
                },
            )

    return merged


async def _merge_asset_soft(
    pool: asyncpg.Pool,
    canonical_id: uuid.UUID,
    duplicate_id: uuid.UUID,
    reason: str,
    evidence: dict,
) -> None:
    """Re-parent child rows, soft-delete duplicate, record in merge_history.

    All operations happen in a single transaction.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Re-parent asset_ips (skip conflicts — canonical may already
            # have the same IP).
            await conn.execute(
                """
                UPDATE asset_ips ai_dup SET asset_id = $1
                WHERE ai_dup.asset_id = $2
                  AND NOT EXISTS (
                    SELECT 1 FROM asset_ips ai_canon
                    WHERE ai_canon.asset_id = $1 AND ai_canon.ip_address = ai_dup.ip_address
                  )
                """,
                canonical_id, duplicate_id,
            )
            await conn.execute(
                "DELETE FROM asset_ips WHERE asset_id = $1",
                duplicate_id,
            )

            # Re-parent asset_hostnames (skip conflicts)
            await conn.execute(
                """
                UPDATE asset_hostnames ah_dup SET asset_id = $1
                WHERE ah_dup.asset_id = $2
                  AND NOT EXISTS (
                    SELECT 1 FROM asset_hostnames ah_canon
                    WHERE ah_canon.asset_id = $1 AND ah_canon.hostname = ah_dup.hostname
                  )
                """,
                canonical_id, duplicate_id,
            )
            await conn.execute(
                "DELETE FROM asset_hostnames WHERE asset_id = $1",
                duplicate_id,
            )

            # Re-parent fingerprints (delete conflicts first, then move)
            await conn.execute(
                """
                DELETE FROM fingerprints fp_dup
                WHERE fp_dup.asset_id = $2
                  AND EXISTS (
                    SELECT 1 FROM fingerprints fp_canon
                    WHERE fp_canon.asset_id = $1
                      AND COALESCE(fp_canon.ja3, '') = COALESCE(fp_dup.ja3, '')
                      AND COALESCE(fp_canon.ja3s, '') = COALESCE(fp_dup.ja3s, '')
                      AND COALESCE(fp_canon.user_agent, '') = COALESCE(fp_dup.user_agent, '')
                      AND COALESCE(fp_canon.dhcp_vendor, '') = COALESCE(fp_dup.dhcp_vendor, '')
                  )
                """,
                canonical_id, duplicate_id,
            )
            await conn.execute(
                "UPDATE fingerprints SET asset_id = $1 WHERE asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent behaviors (skip conflicts on composite key)
            await conn.execute(
                """
                DELETE FROM behaviors b_dup
                WHERE b_dup.asset_id = $2
                  AND EXISTS (
                    SELECT 1 FROM behaviors b_canon
                    WHERE b_canon.asset_id = $1
                      AND b_canon.protocol = b_dup.protocol
                      AND b_canon.port = b_dup.port
                      AND b_canon.service = b_dup.service
                  )
                """,
                canonical_id, duplicate_id,
            )
            await conn.execute(
                "UPDATE behaviors SET asset_id = $1 WHERE asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent connections (both src and dst)
            await conn.execute(
                "UPDATE connections SET src_asset_id = $1 WHERE src_asset_id = $2",
                canonical_id, duplicate_id,
            )
            await conn.execute(
                "UPDATE connections SET dst_asset_id = $1 WHERE dst_asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent dns_queries
            await conn.execute(
                "UPDATE dns_queries SET asset_id = $1 WHERE asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent http_sessions
            await conn.execute(
                "UPDATE http_sessions SET asset_id = $1 WHERE asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent tls_sessions
            await conn.execute(
                "UPDATE tls_sessions SET asset_id = $1 WHERE asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Re-parent alerts
            await conn.execute(
                "UPDATE alerts SET source_asset_id = $1 WHERE source_asset_id = $2",
                canonical_id, duplicate_id,
            )

            # Delete duplicate inference_results (must remove evidence first
            # due to FK constraint inference_evidence → inference_results).
            await conn.execute(
                """
                DELETE FROM inference_evidence
                WHERE inference_id IN (
                    SELECT id FROM inference_results WHERE asset_id = $1
                )
                """,
                duplicate_id,
            )
            await conn.execute(
                "DELETE FROM inference_results WHERE asset_id = $1",
                duplicate_id,
            )

            # Update canonical asset timestamps
            await conn.execute(
                """
                UPDATE assets SET
                    first_seen = LEAST(first_seen, (SELECT first_seen FROM assets WHERE id = $2)),
                    last_seen  = GREATEST(last_seen, (SELECT last_seen FROM assets WHERE id = $2))
                WHERE id = $1
                """,
                canonical_id, duplicate_id,
            )

            # Soft-delete the duplicate (preserve for audit)
            await conn.execute(
                """
                UPDATE assets SET asset_status = 'merged', merged_into = $1
                WHERE id = $2
                """,
                canonical_id, duplicate_id,
            )

            # Record in merge_history
            await conn.execute(
                """
                INSERT INTO merge_history
                    (id, canonical_id, merged_id, merge_reason, merge_evidence)
                VALUES ($1, $2, $3, $4, $5::jsonb)
                """,
                uuid.uuid4(), canonical_id, duplicate_id,
                reason, json.dumps(evidence),
            )
