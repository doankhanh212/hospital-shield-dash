-- Migration 002: Add merge_history table and soft-delete support
-- Date: 2026-04-16
-- Apply: psql -d passive_asset_intel -f passive_asset_intel/migrations/002_merge_history.sql

-- Add merged_into column for soft-delete tracking
ALTER TABLE assets ADD COLUMN IF NOT EXISTS merged_into uuid REFERENCES assets(id) ON DELETE SET NULL;

-- Audit table for all asset merges
CREATE TABLE IF NOT EXISTS merge_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    merged_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    merge_reason varchar NOT NULL,
    merge_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_merge_history_canonical ON merge_history (canonical_id);
CREATE INDEX IF NOT EXISTS idx_merge_history_merged ON merge_history (merged_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets (asset_status) WHERE asset_status != 'active';
