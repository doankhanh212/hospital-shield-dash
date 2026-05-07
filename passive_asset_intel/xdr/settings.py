"""XDR settings KV store — API keys and runtime configuration.

Values are stored plaintext.  An in-memory cache (60 s TTL) keeps the hot
path off the DB; ``set_setting`` invalidates the cache for the affected key.
"""

from __future__ import annotations

import time
from typing import Any

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

_CACHE_TTL = 60.0
_cache: dict[str, tuple[float, str | None]] = {}


async def get_setting(pool: asyncpg.Pool, key: str) -> str | None:
    """Return the setting value or None if unset.

    Cached for ``_CACHE_TTL`` seconds to avoid hammering the DB on the hot
    detection path.
    """
    now = time.monotonic()
    cached = _cache.get(key)
    if cached is not None and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    async with pool.acquire() as conn:
        value = await conn.fetchval(
            "SELECT value FROM xdr_settings WHERE key = $1", key
        )
    _cache[key] = (now, value)
    return value


async def set_setting(pool: asyncpg.Pool, key: str, value: str) -> dict[str, Any]:
    """Upsert a setting and invalidate its cache entry."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO xdr_settings (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key) DO UPDATE SET
                value      = EXCLUDED.value,
                updated_at = NOW()
            RETURNING key, value, updated_at
            """,
            key,
            value,
        )
    _cache.pop(key, None)
    logger.info("XDR setting updated", extra={"key": key})
    return dict(row)


async def list_settings(pool: asyncpg.Pool) -> list[dict[str, Any]]:
    """Return all settings.  Values are masked except for the last 4 chars."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT key, value, updated_at FROM xdr_settings ORDER BY key"
        )
    out: list[dict[str, Any]] = []
    for r in rows:
        v = r["value"]
        masked = "***" + v[-4:] if v and len(v) > 4 else "***"
        out.append({
            "key":        r["key"],
            "value":      masked,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        })
    return out


async def delete_setting(pool: asyncpg.Pool, key: str) -> bool:
    """Remove a setting.  Returns True if a row was deleted."""
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM xdr_settings WHERE key = $1", key)
    _cache.pop(key, None)
    return result.endswith(" 1")
