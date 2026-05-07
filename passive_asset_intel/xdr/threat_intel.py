"""Threat intelligence enrichment — VirusTotal + AbuseIPDB.

Both clients are async (httpx) with strict 2-second timeouts and a shared
in-memory TTL cache (1 hour) keyed by IP.  Private / link-local IPs are
short-circuited to a zero-score result and never hit the wire.

API keys are read on-demand from ``xdr_settings`` via ``get_setting``; if
either key is missing, that lookup is skipped (returns zero) so the pipeline
runs degraded but functional.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import asyncpg
import httpx

from passive_asset_intel.utils.logger import setup_logger
from passive_asset_intel.xdr.settings import get_setting

logger = setup_logger(__name__)

# ── Tunables ─────────────────────────────────────────────────────────────────

INTEL_TIMEOUT_S = 2.0
CACHE_TTL_S     = 3600.0          # 1 hour
NEGATIVE_TTL_S  = 300.0           # 5 min for failures, to avoid hammering APIs

VT_URL          = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/check"

VT_KEY_NAME     = "VT_API_KEY"
ABUSE_KEY_NAME  = "ABUSEIPDB_API_KEY"

EMPTY_RESULT: dict[str, int] = {
    "vt_malicious":  0,
    "vt_suspicious": 0,
    "abuse_score":   0,
}

# ── Cache ────────────────────────────────────────────────────────────────────

_cache: dict[str, tuple[float, dict[str, int]]] = {}
_cache_lock = asyncio.Lock()


def _cache_get(ip: str) -> dict[str, int] | None:
    entry = _cache.get(ip)
    if entry is None:
        return None
    ts, val = entry
    if (time.monotonic() - ts) > CACHE_TTL_S:
        return None
    return val


def _cache_set(ip: str, val: dict[str, int], ttl: float = CACHE_TTL_S) -> None:
    # Stamp the entry with an offset so it expires after `ttl` seconds.
    expiry_offset = time.monotonic() - (CACHE_TTL_S - ttl)
    _cache[ip] = (expiry_offset, val)


# ── IP filtering ─────────────────────────────────────────────────────────────

def _is_routable_public(ip: str) -> bool:
    """Skip private/loopback/link-local/multicast IPs — intel APIs reject them."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


# ── VirusTotal ───────────────────────────────────────────────────────────────

async def query_virustotal(client: httpx.AsyncClient, ip: str, api_key: str) -> dict[str, int]:
    """Return ``{vt_malicious, vt_suspicious}`` from VT v3 for *ip*."""
    try:
        resp = await client.get(
            VT_URL.format(ip=ip),
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=INTEL_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        logger.warning("VT request failed", extra={"ip": ip, "error": str(exc)})
        return {"vt_malicious": 0, "vt_suspicious": 0}

    if resp.status_code != 200:
        logger.warning("VT non-200", extra={"ip": ip, "status": resp.status_code})
        return {"vt_malicious": 0, "vt_suspicious": 0}

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_malicious":  int(stats.get("malicious", 0)),
            "vt_suspicious": int(stats.get("suspicious", 0)),
        }
    except (KeyError, ValueError, TypeError):
        return {"vt_malicious": 0, "vt_suspicious": 0}


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

async def query_abuseipdb(client: httpx.AsyncClient, ip: str, api_key: str) -> dict[str, int]:
    """Return ``{abuse_score}`` (0-100) from AbuseIPDB for *ip*."""
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=INTEL_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        logger.warning("AbuseIPDB request failed", extra={"ip": ip, "error": str(exc)})
        return {"abuse_score": 0}

    if resp.status_code != 200:
        logger.warning("AbuseIPDB non-200", extra={"ip": ip, "status": resp.status_code})
        return {"abuse_score": 0}

    try:
        score = int(resp.json()["data"]["abuseConfidenceScore"])
        return {"abuse_score": max(0, min(100, score))}
    except (KeyError, ValueError, TypeError):
        return {"abuse_score": 0}


# ── Combined enrichment ──────────────────────────────────────────────────────

async def enrich(pool: asyncpg.Pool, ip: str) -> dict[str, int]:
    """Lookup VT + AbuseIPDB for *ip*, returning a flat enrichment dict.

    Always returns the shape::

        {"vt_malicious": int, "vt_suspicious": int, "abuse_score": int}

    Private / non-routable IPs short-circuit to zero scores.  Cache hits skip
    the network entirely.  Network errors cache a negative result for 5 min
    so the pipeline never blocks.
    """
    if not _is_routable_public(ip):
        return dict(EMPTY_RESULT)

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    async with _cache_lock:
        # Double-check after acquiring the lock — another coroutine may have
        # filled the cache while we waited.
        cached = _cache_get(ip)
        if cached is not None:
            return cached

        vt_key, abuse_key = await asyncio.gather(
            get_setting(pool, VT_KEY_NAME),
            get_setting(pool, ABUSE_KEY_NAME),
        )

        if not vt_key and not abuse_key:
            _cache_set(ip, dict(EMPTY_RESULT), ttl=NEGATIVE_TTL_S)
            return dict(EMPTY_RESULT)

        async with httpx.AsyncClient(timeout=INTEL_TIMEOUT_S) as client:
            tasks: list = []
            if vt_key:
                tasks.append(query_virustotal(client, ip, vt_key))
            else:
                tasks.append(_noop_vt())
            if abuse_key:
                tasks.append(query_abuseipdb(client, ip, abuse_key))
            else:
                tasks.append(_noop_abuse())

            try:
                vt_res, abuse_res = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=False),
                    timeout=INTEL_TIMEOUT_S * 1.5,
                )
            except asyncio.TimeoutError:
                logger.warning("Threat intel timeout", extra={"ip": ip})
                _cache_set(ip, dict(EMPTY_RESULT), ttl=NEGATIVE_TTL_S)
                return dict(EMPTY_RESULT)

        result = {**vt_res, **abuse_res}
        # Fill any missing keys with zeros so the shape is stable.
        for k, v in EMPTY_RESULT.items():
            result.setdefault(k, v)

        _cache_set(ip, result, ttl=CACHE_TTL_S)
        return result


async def _noop_vt() -> dict[str, int]:
    return {"vt_malicious": 0, "vt_suspicious": 0}


async def _noop_abuse() -> dict[str, int]:
    return {"abuse_score": 0}


def clear_cache() -> None:
    """Test helper — wipes the TTL cache."""
    _cache.clear()
