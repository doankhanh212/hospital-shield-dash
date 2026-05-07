"""Rogue-device detector.

Fires the ``rogue_device`` anomaly when an unfamiliar MAC appears on the
LAN.  Severity scales by how unidentifiable the MAC is:

    medium   — vendor known (legitimate but unmanaged)
    high     — vendor unknown / locally-administered (could be anything)

Hooks into the existing XDR pipeline as an additive call after we've
discovered the asset's MAC + vendor.  Results land in xdr_anomalies via
the standard upsert path so triage UI / correlation / scoring all pick
them up automatically.
"""

from __future__ import annotations

import asyncpg

from passive_asset_intel.utils.logger import setup_logger
from passive_asset_intel.xdr.fingerprint import Fingerprint, _is_locally_administered

logger = setup_logger(__name__)

# Window in days to consider a MAC "previously known" — older than this
# and we still raise the rogue alert.  Tuneable.
SEEN_WINDOW_DAYS = 30


async def is_known_mac(pool: asyncpg.Pool, mac: str) -> bool:
    """True if this MAC has been seen on the LAN inside SEEN_WINDOW_DAYS."""
    async with pool.acquire() as conn:
        row = await conn.fetchval(
            f"""
            SELECT 1 FROM assets
            WHERE  mac_address = $1
              AND  first_seen   < NOW() - INTERVAL '{SEEN_WINDOW_DAYS} days'
            LIMIT  1
            """,
            mac,
        )
    return row is not None


def build_rogue_alert(
    *,
    asset_ip: str,
    mac: str,
    vendor: str | None,
    fp: Fingerprint | None = None,
) -> dict:
    """Compose an alert dict shaped for ``upsert_anomaly`` + scoring.

    Severity heuristic:
        - locally-administered MAC OR no vendor → 'high'
        - vendor known but device unmanaged    → 'medium'
    """
    locally_admin = _is_locally_administered(mac)
    vendor_known  = bool(vendor) and vendor.lower() not in ("unknown", "")

    if locally_admin or not vendor_known:
        sev, dev = "high", 6.0
    else:
        sev, dev = "medium", 3.0

    evidence: dict = {
        "rogue_mac":          mac,
        "rogue_vendor":       vendor or "unknown",
        "locally_administered": locally_admin,
    }
    if fp:
        evidence["fingerprint_guess"] = fp.device_type
        evidence["fingerprint_conf"]  = fp.confidence

    return {
        "asset":     asset_ip,
        "type":      "rogue_device",
        "deviation": dev,
        "evidence":  evidence,
    }


async def evaluate(
    pool: asyncpg.Pool,
    *,
    asset_ip: str,
    mac: str | None,
    vendor: str | None,
    fp: Fingerprint | None = None,
) -> dict | None:
    """If *mac* qualifies as rogue, return an alert dict for upsert; else None.

    Idempotent: relying on (asset_id, type) uniqueness in xdr_anomalies, so
    repeated firing simply bumps ``count`` and refreshes ``last_seen``.
    """
    if not mac:
        return None
    if mac.startswith("ip:"):
        return None

    try:
        if await is_known_mac(pool, mac):
            return None
    except asyncpg.PostgresError:
        # If the lookup fails we conservatively skip — better no false positive
        return None

    alert = build_rogue_alert(asset_ip=asset_ip, mac=mac, vendor=vendor, fp=fp)
    logger.info(
        "Rogue device candidate",
        extra={"asset": asset_ip, "mac": mac, "vendor": vendor or "?",
               "severity_hint": "high" if not vendor or _is_locally_administered(mac) else "medium"},
    )
    return alert
