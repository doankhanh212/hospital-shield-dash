"""XDR database schema — idempotent DDL for all XDR tables.

Tables are namespaced ``xdr_*`` to avoid colliding with the legacy
``assets`` table used by the MAC-keyed device classifier.
"""

from __future__ import annotations

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

_DDL = """
-- ── Anomaly + incident tables (existing) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS xdr_anomalies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    TEXT        NOT NULL,
    type        TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    score       FLOAT       NOT NULL DEFAULT 0.0,
    description TEXT        NOT NULL DEFAULT '',
    evidence    JSONB       NOT NULL DEFAULT '{}',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    count       INT         NOT NULL DEFAULT 1,
    CONSTRAINT uq_xdr_anomaly_asset_type UNIQUE (asset_id, type)
);
CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_asset_id  ON xdr_anomalies (asset_id);
CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_last_seen ON xdr_anomalies (last_seen DESC);

CREATE TABLE IF NOT EXISTS xdr_incidents (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id       TEXT        NOT NULL,
    severity       TEXT        NOT NULL,
    anomaly_types  JSONB       NOT NULL DEFAULT '[]',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xdr_incidents_asset_id  ON xdr_incidents (asset_id);
CREATE INDEX IF NOT EXISTS idx_xdr_incidents_last_seen ON xdr_incidents (last_seen DESC);

-- ── Soft FK linkage: IP-keyed anomalies → MAC-keyed legacy assets table.
--    NULL when the source IP cannot be resolved to a known asset (e.g. external
--    attackers).  ON DELETE SET NULL preserves XDR history if an asset is purged.
ALTER TABLE xdr_anomalies
    ADD COLUMN IF NOT EXISTS asset_uuid UUID
        REFERENCES assets(id) ON DELETE SET NULL;
ALTER TABLE xdr_incidents
    ADD COLUMN IF NOT EXISTS asset_uuid UUID
        REFERENCES assets(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_asset_uuid ON xdr_anomalies (asset_uuid)
    WHERE asset_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_xdr_incidents_asset_uuid ON xdr_incidents (asset_uuid)
    WHERE asset_uuid IS NOT NULL;

-- ── Triage workflow fields (additive) ────────────────────────────────────
-- status:  new | investigating | escalated | resolved | false_positive
ALTER TABLE xdr_anomalies
    ADD COLUMN IF NOT EXISTS status      VARCHAR(16)  NOT NULL DEFAULT 'new',
    ADD COLUMN IF NOT EXISTS assigned_to TEXT,
    ADD COLUMN IF NOT EXISTS note        TEXT,
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_status      ON xdr_anomalies (status);
CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_assigned_to ON xdr_anomalies (assigned_to)
    WHERE assigned_to IS NOT NULL;

-- ── Audit log: every analyst action becomes a row here ──────────────────
CREATE TABLE IF NOT EXISTS xdr_audit_log (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type  VARCHAR(32)  NOT NULL,   -- anomaly | incident
    entity_id    UUID         NOT NULL,
    action       VARCHAR(32)  NOT NULL,   -- assign | status_change | note | escalate
    old_value    JSONB,
    new_value    JSONB,
    actor        TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xdr_audit_entity ON xdr_audit_log (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_xdr_audit_created ON xdr_audit_log (created_at DESC);

-- ── Multi-sensor readiness ───────────────────────────────────────────────
-- Optional sensor identifier — supports a future deployment where multiple
-- Zeek instances feed the same database.  Nullable so single-sensor setups
-- (today) keep working without any code change.
ALTER TABLE xdr_anomalies     ADD COLUMN IF NOT EXISTS sensor_id TEXT;
ALTER TABLE xdr_incidents     ADD COLUMN IF NOT EXISTS sensor_id TEXT;
ALTER TABLE xdr_assets        ADD COLUMN IF NOT EXISTS sensor_id TEXT;
ALTER TABLE xdr_asset_profiles ADD COLUMN IF NOT EXISTS sensor_id TEXT;
CREATE INDEX IF NOT EXISTS idx_xdr_anomalies_sensor ON xdr_anomalies (sensor_id) WHERE sensor_id IS NOT NULL;

-- ── Asset registry (XDR-owned, IP-keyed) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS xdr_assets (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          TEXT        NOT NULL UNIQUE,
    mac         TEXT,
    device_type TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_xdr_assets_last_seen ON xdr_assets (last_seen DESC);

-- ── Behavioral baselines (one row per IP) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS xdr_asset_profiles (
    asset_id        TEXT        PRIMARY KEY,
    avg_conn        FLOAT       NOT NULL DEFAULT 0.0,
    avg_dns         FLOAT       NOT NULL DEFAULT 0.0,
    avg_bytes_out   FLOAT       NOT NULL DEFAULT 0.0,
    avg_bytes_in    FLOAT       NOT NULL DEFAULT 0.0,
    avg_unique_ports   FLOAT    NOT NULL DEFAULT 0.0,
    avg_unique_domains FLOAT    NOT NULL DEFAULT 0.0,
    common_ports    JSONB       NOT NULL DEFAULT '{}',
    common_domains  JSONB       NOT NULL DEFAULT '{}',
    common_ja3      JSONB       NOT NULL DEFAULT '{}',
    sample_count    INT         NOT NULL DEFAULT 0,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Settings KV store (API keys, etc.) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS xdr_settings (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def ensure_xdr_schema(pool: asyncpg.Pool) -> None:
    """Create all XDR tables and indexes if they do not already exist."""
    async with pool.acquire() as conn:
        await conn.execute(_DDL)
    logger.info("XDR schema ensured")


async def backfill_asset_uuid_links(pool: asyncpg.Pool) -> dict[str, int]:
    """Resolve any unlinked xdr_anomalies/xdr_incidents to legacy assets via asset_ips.

    Safe to call on startup — only fills NULL slots.  Returns affected counts
    per table for observability.
    """
    async with pool.acquire() as conn:
        a = await conn.execute(
            """
            UPDATE xdr_anomalies a
            SET    asset_uuid = ai.asset_id
            FROM   asset_ips ai
            WHERE  a.asset_uuid IS NULL
              AND  ai.ip_address = a.asset_id::inet
            """,
        )
        i = await conn.execute(
            """
            UPDATE xdr_incidents x
            SET    asset_uuid = ai.asset_id
            FROM   asset_ips ai
            WHERE  x.asset_uuid IS NULL
              AND  ai.ip_address = x.asset_id::inet
            """,
        )
    n_a = int(a.split()[-1]) if a.startswith("UPDATE") else 0
    n_i = int(i.split()[-1]) if i.startswith("UPDATE") else 0
    if n_a or n_i:
        logger.info("XDR asset_uuid backfill", extra={"anomalies": n_a, "incidents": n_i})
    return {"anomalies": n_a, "incidents": n_i}
