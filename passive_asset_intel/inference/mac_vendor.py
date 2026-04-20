"""MAC OUI vendor lookup with persistent file cache.

Designed to make inference fast over thousands of assets:

1. **Persistent file cache** (``.mac_vendor_cache.json``) — loaded on module
   import, saved after every new lookup.  OUI → vendor mappings never expire.

2. **IP-only fallback skip** — MACs of the form ``ip:<addr>`` (used when we
   only observed an asset via IP) return "Unknown" immediately.

3. **Rate limiting with jitter** — 1 req/s ± 20 % to avoid thundering herd
   against the free macvendors.com API.

Usage::

    resolver = MacVendorResolver()
    vendor = await resolver.lookup("00:1A:2B:AA:BB:CC")
"""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

import httpx

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

API_URL = "https://api.macvendors.com/{oui}"
MAX_VENDOR_LEN = 50
REQUEST_INTERVAL = 1.0  # seconds between requests (free-tier limit)
JITTER_MIN = 0.8
JITTER_MAX = 1.2

CACHE_FILE: Path = (
    Path(__file__).resolve().parent.parent / ".mac_vendor_cache.json"
)

def _load_cache_file() -> dict[str, str]:
    """Load the persistent OUI → vendor cache from disk.

    Returns:
        Dict of OUI → vendor.  Empty dict on any read/parse error.
    """
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k).upper(): str(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "Failed to load MAC vendor cache — starting empty",
            extra={"file": str(CACHE_FILE), "error": str(exc)},
        )
    return {}


def _save_cache_file(cache: dict[str, str]) -> None:
    """Persist the OUI → vendor cache to disk atomically."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2, sort_keys=True)
        tmp.replace(CACHE_FILE)
    except OSError as exc:
        logger.warning(
            "Failed to save MAC vendor cache",
            extra={"file": str(CACHE_FILE), "error": str(exc)},
        )


# ── Module-level cache, initialized on import ───────────────────────
_MODULE_CACHE: dict[str, str] = _load_cache_file()

logger.info(
    "MAC vendor cache loaded",
    extra={"cache_entries": len(_MODULE_CACHE), "cache_file": str(CACHE_FILE)},
)


class MacVendorResolver:
    """Async MAC OUI → vendor string resolver with persistent caching and rate limiting."""

    def __init__(self) -> None:
        """Initialize the resolver — reuses the module-level cache."""
        # Shared across instances so multiple resolvers don't duplicate API calls
        self._cache: dict[str, str] = _MODULE_CACHE
        self._last_request: float = 0.0
        self._client: httpx.AsyncClient | None = None
        self._cache_dirty: bool = False

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create the shared httpx async client.

        Returns:
            An httpx.AsyncClient instance.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client and flush the cache to disk."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
        if self._cache_dirty:
            _save_cache_file(self._cache)
            self._cache_dirty = False

    def _extract_oui(self, mac: str) -> str | None:
        """Extract the first 8 characters (OUI) from a MAC address.

        Skips synthetic ``ip:`` prefix addresses.

        Args:
            mac: MAC address string (e.g. "AA:BB:CC:DD:EE:FF").

        Returns:
            The OUI portion (e.g. "AA:BB:CC"), or None if the MAC is invalid
            or is a synthetic IP-only address.
        """
        if not mac or mac.startswith("ip:"):
            return None
        # Normalize separators
        cleaned = mac.upper().replace("-", ":").replace(".", ":")
        parts = cleaned.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3])
        # Handle unseparated MACs (e.g. "AABBCCDDEEFF")
        if len(cleaned.replace(":", "")) >= 6:
            raw = cleaned.replace(":", "")
            return f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"
        return None

    async def _rate_limit(self) -> None:
        """Enforce the 1 req/s rate limit with ±20 % jitter."""
        interval = REQUEST_INTERVAL * random.uniform(JITTER_MIN, JITTER_MAX)
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request
        if elapsed < interval:
            await asyncio.sleep(interval - elapsed)
        self._last_request = asyncio.get_event_loop().time()

    async def lookup(self, mac: str) -> str:
        """Look up the vendor for a MAC address via OUI.

        Resolution order:
        1. Synthetic ``ip:*`` MAC  → "Unknown" (no API call).
        2. Cache hit               → cached value (no API call).
        3. API lookup              → on success cache and return vendor;
                                     on failure cache and return "Unknown".

        Args:
            mac: MAC address string.

        Returns:
            Vendor name (max 50 chars), or "Unknown" on any failure / skip.
        """
        # IP-only synthetic fallback — skip entirely
        if not mac or mac.startswith("ip:"):
            return "Unknown"

        oui = self._extract_oui(mac)
        if oui is None:
            return "Unknown"

        # Check cache (includes KNOWN_VENDORS seeded on import)
        if oui in self._cache:
            return self._cache[oui]

        # Rate-limited API call
        await self._rate_limit()
        client = await self._get_client()

        try:
            url = API_URL.format(oui=oui)
            resp = await client.get(url)

            if resp.status_code == 429:
                # Rate limited — back off 60s and retry once
                logger.warning("MAC vendor API rate limited, waiting 60s")
                await asyncio.sleep(60.0)
                self._last_request = asyncio.get_event_loop().time()
                resp = await client.get(url)

            if resp.status_code == 200:
                vendor = resp.text.strip()[:MAX_VENDOR_LEN]
                if vendor:
                    self._cache[oui] = vendor
                    self._cache_dirty = True
                    _save_cache_file(self._cache)
                    return vendor

            if resp.status_code == 404:
                # OUI not found in database
                self._cache[oui] = "Unknown"
                self._cache_dirty = True
                _save_cache_file(self._cache)
                return "Unknown"

            logger.warning(
                "MAC vendor API error",
                extra={"oui": oui, "status": resp.status_code},
            )
        except (httpx.HTTPError, OSError) as exc:
            logger.warning(
                "MAC vendor API request failed",
                extra={"oui": oui, "error": str(exc)},
            )

        # On any unexpected error, cache negative result so we don't retry
        self._cache[oui] = "Unknown"
        self._cache_dirty = True
        _save_cache_file(self._cache)
        return "Unknown"
