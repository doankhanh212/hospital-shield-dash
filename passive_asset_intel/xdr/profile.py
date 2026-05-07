"""XDR profile engine — per-asset behavioral baselines.

Maintains EWMA averages and frequency maps (top-N) for each asset.  The
baseline is consulted by the detection layer to decide whether activity is
abnormal *relative to that asset's history* — not just against static
thresholds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

# ── Tunables ─────────────────────────────────────────────────────────────────

EWMA_ALPHA          = 0.2     # smoothing factor — lower = slower adaptation
TOPN_FREQ           = 50      # max keys retained in each frequency map
COMMON_MIN_COUNT    = 2       # an entry must be seen ≥ N times to be "common"
WARMUP_SAMPLES      = 5       # baseline considered "cold" until N flushes seen


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    """In-memory view of an asset's behavioral profile."""
    asset_id:           str
    avg_conn:           float = 0.0
    avg_dns:            float = 0.0
    avg_bytes_out:      float = 0.0
    avg_bytes_in:       float = 0.0
    avg_unique_ports:   float = 0.0
    avg_unique_domains: float = 0.0
    common_ports:       dict[str, int] = field(default_factory=dict)
    common_domains:     dict[str, int] = field(default_factory=dict)
    common_ja3:         dict[str, int] = field(default_factory=dict)
    sample_count:       int   = 0

    @property
    def is_warm(self) -> bool:
        """True once we have enough samples to trust the baseline."""
        return self.sample_count >= WARMUP_SAMPLES


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ewma(prev: float, current: float, samples: int) -> float:
    """Exponentially-weighted moving average.

    The first sample is taken as-is so a cold baseline does not stay anchored
    at zero forever.
    """
    if samples == 0:
        return float(current)
    return EWMA_ALPHA * float(current) + (1.0 - EWMA_ALPHA) * prev


def _merge_freq(freq: dict[str, int], items, weight: int = 1) -> dict[str, int]:
    """Increment frequencies for `items`, then trim to TOPN_FREQ entries."""
    for it in items:
        key = str(it)
        freq[key] = freq.get(key, 0) + weight
    if len(freq) <= TOPN_FREQ:
        return freq
    # Keep the TOPN_FREQ highest-count entries (deterministic by key on tie)
    top = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:TOPN_FREQ]
    return dict(top)


def _is_common(freq: dict[str, int], key: str) -> bool:
    return freq.get(str(key), 0) >= COMMON_MIN_COUNT


# ── Public API ───────────────────────────────────────────────────────────────

async def compute_baseline(pool: asyncpg.Pool, asset_id: str) -> Baseline:
    """Load the baseline for an asset.  Returns a cold (zeroed) baseline if
    the asset has never been profiled before."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT avg_conn, avg_dns, avg_bytes_out, avg_bytes_in,
                   avg_unique_ports, avg_unique_domains,
                   common_ports, common_domains, common_ja3,
                   sample_count
            FROM   xdr_asset_profiles
            WHERE  asset_id = $1
            """,
            asset_id,
        )
    if row is None:
        return Baseline(asset_id=asset_id)
    return Baseline(
        asset_id           = asset_id,
        avg_conn           = float(row["avg_conn"]),
        avg_dns            = float(row["avg_dns"]),
        avg_bytes_out      = float(row["avg_bytes_out"]),
        avg_bytes_in       = float(row["avg_bytes_in"]),
        avg_unique_ports   = float(row["avg_unique_ports"]),
        avg_unique_domains = float(row["avg_unique_domains"]),
        common_ports       = _coerce_jsonb(row["common_ports"]),
        common_domains     = _coerce_jsonb(row["common_domains"]),
        common_ja3         = _coerce_jsonb(row["common_ja3"]),
        sample_count       = int(row["sample_count"]),
    )


async def update_profile(
    pool: asyncpg.Pool,
    asset_id: str,
    activity: dict[str, Any],
    *,
    ports: list[int] | None = None,
    domains: list[str] | None = None,
    ja3s: list[str] | None = None,
) -> Baseline:
    """Update the asset's baseline with the latest activity window.

    Args:
        pool:     asyncpg pool.
        asset_id: Source IP (used as primary key).
        activity: Window snapshot dict from WindowAggregator.flush().
        ports / domains / ja3s: Raw observations from the window — used to
            update the frequency maps.  Pass empty lists if none observed.

    Returns:
        The updated Baseline (post-merge, post-EWMA).
    """
    base = await compute_baseline(pool, asset_id)

    new_avg_conn         = _ewma(base.avg_conn,           activity["conn_count"],     base.sample_count)
    new_avg_dns          = _ewma(base.avg_dns,            activity["dns_count"],      base.sample_count)
    new_avg_bytes_out    = _ewma(base.avg_bytes_out,      activity["bytes_out"],      base.sample_count)
    new_avg_bytes_in     = _ewma(base.avg_bytes_in,       activity["bytes_in"],       base.sample_count)
    new_avg_uports       = _ewma(base.avg_unique_ports,   activity["unique_ports"],   base.sample_count)
    new_avg_udomains     = _ewma(base.avg_unique_domains, activity["unique_domains"], base.sample_count)

    new_ports   = _merge_freq(dict(base.common_ports),   ports   or [])
    new_domains = _merge_freq(dict(base.common_domains), domains or [])
    new_ja3     = _merge_freq(dict(base.common_ja3),     ja3s    or [])

    new_count = base.sample_count + 1

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO xdr_asset_profiles (
                asset_id, avg_conn, avg_dns, avg_bytes_out, avg_bytes_in,
                avg_unique_ports, avg_unique_domains,
                common_ports, common_domains, common_ja3,
                sample_count, last_updated
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9::jsonb, $10::jsonb,
                $11, NOW()
            )
            ON CONFLICT (asset_id) DO UPDATE SET
                avg_conn           = EXCLUDED.avg_conn,
                avg_dns            = EXCLUDED.avg_dns,
                avg_bytes_out      = EXCLUDED.avg_bytes_out,
                avg_bytes_in       = EXCLUDED.avg_bytes_in,
                avg_unique_ports   = EXCLUDED.avg_unique_ports,
                avg_unique_domains = EXCLUDED.avg_unique_domains,
                common_ports       = EXCLUDED.common_ports,
                common_domains     = EXCLUDED.common_domains,
                common_ja3         = EXCLUDED.common_ja3,
                sample_count       = EXCLUDED.sample_count,
                last_updated       = NOW()
            """,
            asset_id,
            new_avg_conn, new_avg_dns, new_avg_bytes_out, new_avg_bytes_in,
            new_avg_uports, new_avg_udomains,
            json.dumps(new_ports), json.dumps(new_domains), json.dumps(new_ja3),
            new_count,
        )

    return Baseline(
        asset_id           = asset_id,
        avg_conn           = new_avg_conn,
        avg_dns            = new_avg_dns,
        avg_bytes_out      = new_avg_bytes_out,
        avg_bytes_in       = new_avg_bytes_in,
        avg_unique_ports   = new_avg_uports,
        avg_unique_domains = new_avg_udomains,
        common_ports       = new_ports,
        common_domains     = new_domains,
        common_ja3         = new_ja3,
        sample_count       = new_count,
    )


def is_common_port(base: Baseline, port: int) -> bool:
    return _is_common(base.common_ports, str(port))


def is_common_domain(base: Baseline, domain: str) -> bool:
    return _is_common(base.common_domains, domain)


def is_common_ja3(base: Baseline, ja3: str) -> bool:
    return _is_common(base.common_ja3, ja3)


# ── Internal ─────────────────────────────────────────────────────────────────

def _coerce_jsonb(val) -> dict[str, int]:
    """asyncpg may hand us either a Python dict or a raw JSON string."""
    if val is None:
        return {}
    if isinstance(val, dict):
        return {str(k): int(v) for k, v in val.items()}
    if isinstance(val, str):
        try:
            decoded = json.loads(val)
            if isinstance(decoded, dict):
                return {str(k): int(v) for k, v in decoded.items()}
        except json.JSONDecodeError:
            pass
    return {}
