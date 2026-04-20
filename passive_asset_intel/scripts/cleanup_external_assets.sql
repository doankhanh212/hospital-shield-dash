-- Cleanup external IP-only assets (keep only 103.98.152.0/24)
-- Safe deletion: only removes assets where mac_address LIKE 'ip:%' AND no IP in local subnets
-- Wraps in transaction so it can be rolled back if counts look wrong.

\set ON_ERROR_STOP on

BEGIN;

-- Snapshot before
SELECT 'BEFORE' AS phase, COUNT(*) AS total_assets FROM assets;

-- Build temp table of asset IDs to delete
CREATE TEMP TABLE assets_to_delete ON COMMIT DROP AS
SELECT a.id
FROM assets a
WHERE a.mac_address LIKE 'ip:%'
  AND NOT EXISTS (
    SELECT 1 FROM asset_ips ai
    WHERE ai.asset_id = a.id
      AND ai.ip_address <<= '103.98.152.0/24'::inet
  );

SELECT 'TO_DELETE' AS phase, COUNT(*) AS n FROM assets_to_delete;

-- Cascade delete child rows
-- alerts uses ON DELETE SET NULL on source_asset_id, so no manual cleanup needed
DELETE FROM asset_hostnames        WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM asset_ips              WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM asset_tags             WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM asset_vulnerabilities  WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM behaviors              WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM connections            WHERE src_asset_id IN (SELECT id FROM assets_to_delete)
                                      OR dst_asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM dns_queries            WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM fingerprints           WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM http_sessions          WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM tls_sessions           WHERE asset_id IN (SELECT id FROM assets_to_delete);
DELETE FROM inference_evidence     WHERE inference_id IN (
    SELECT id FROM inference_results WHERE asset_id IN (SELECT id FROM assets_to_delete)
);
DELETE FROM inference_results      WHERE asset_id IN (SELECT id FROM assets_to_delete);

-- Finally delete the assets themselves
DELETE FROM assets WHERE id IN (SELECT id FROM assets_to_delete);

-- Snapshot after
SELECT 'AFTER' AS phase, COUNT(*) AS total_assets FROM assets;

COMMIT;

-- Final breakdown
SELECT
    COALESCE(ir.device_type, 'NULL/Unknown') AS device_type,
    COUNT(*) AS n
FROM assets a
LEFT JOIN inference_results ir ON ir.asset_id = a.id
GROUP BY 1
ORDER BY 2 DESC;
