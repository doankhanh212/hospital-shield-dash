"""Database writer for inference results.

Upserts classification results into ``inference_results`` and refreshes
the associated ``inference_evidence`` and ``inference_anomalies`` rows,
all within a single transaction.
Also patches the parent ``assets`` row with the inferred vendor and confidence.

Usage::

    await upsert_inference(pool, asset_id_str, result_dict)
"""

from __future__ import annotations

import json
import uuid

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)


async def ensure_unique_constraint(pool: asyncpg.Pool) -> None:
    """Create the unique constraint on inference_results(asset_id) if missing.

    This is idempotent — safe to call on every run.

    Args:
        pool: asyncpg connection pool.
    """
    async with pool.acquire() as conn:
        exists = await conn.fetchval("""
            SELECT 1 FROM pg_constraint
            WHERE conname = 'uq_inference_results_asset'
        """)
        if not exists:
            await conn.execute("""
                ALTER TABLE inference_results
                ADD CONSTRAINT uq_inference_results_asset UNIQUE (asset_id)
            """)
            logger.info("Created unique constraint uq_inference_results_asset")


async def upsert_inference(
    pool: asyncpg.Pool,
    asset_id: str,
    result: dict,
) -> None:
    """Write a classification result to the database.

    Performs all operations in a single transaction:
    1. UPSERT into inference_results (ON CONFLICT asset_id).
    2. DELETE + re-INSERT inference_evidence rows.
    3. UPDATE the parent assets row (vendor, confidence_score).

    Args:
        pool: asyncpg connection pool.
        asset_id: UUID string of the asset.
        result: Classification result from device_classifier.classify_asset().
    """
    asset_uuid = uuid.UUID(asset_id)

    async with pool.acquire() as conn:
        async with conn.transaction():
            # 1. Upsert inference_results
            inference_id = await conn.fetchval(
                """
                INSERT INTO inference_results
                    (id, asset_id, device_type, os, os_version, cpe,
                     confidence, method, behavior_type, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                ON CONFLICT (asset_id) DO UPDATE SET
                    device_type   = EXCLUDED.device_type,
                    os            = EXCLUDED.os,
                    os_version    = EXCLUDED.os_version,
                    cpe           = EXCLUDED.cpe,
                    confidence    = EXCLUDED.confidence,
                    method        = EXCLUDED.method,
                    behavior_type = EXCLUDED.behavior_type,
                    created_at    = NOW()
                RETURNING id
                """,
                uuid.uuid4(),
                asset_uuid,
                result["device_type"],
                result["os"],
                result.get("os_version"),
                result.get("cpe"),
                result["confidence"],
                result["method"],
                result.get("behavior_type"),
            )

            # 2. Refresh evidence: delete old, insert new
            await conn.execute(
                "DELETE FROM inference_evidence WHERE inference_id = $1",
                inference_id,
            )

            evidence_rows = [
                (
                    uuid.uuid4(),
                    inference_id,
                    ev["evidence_type"],
                    ev["value"],
                    ev["weight"],
                )
                for ev in result.get("evidence", [])
            ]
            if evidence_rows:
                await conn.executemany(
                    """
                    INSERT INTO inference_evidence
                        (id, inference_id, evidence_type, value, weight)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    evidence_rows,
                )

            # 2b. Refresh anomalies: delete old, insert new
            await conn.execute(
                "DELETE FROM inference_anomalies WHERE inference_id = $1",
                inference_id,
            )

            anomaly_rows = [
                (
                    uuid.uuid4(),
                    inference_id,
                    anom["id"],
                    anom["severity"],
                    anom["message"],
                    json.dumps(anom.get("evidence", {})),
                )
                for anom in result.get("anomalies", [])
            ]
            if anomaly_rows:
                await conn.executemany(
                    """
                    INSERT INTO inference_anomalies
                        (id, inference_id, anomaly_id, severity, message, evidence)
                    VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                    """,
                    anomaly_rows,
                )

            # 3. Patch the parent asset row
            vendor = result.get("vendor")
            confidence = result.get("confidence", 0.0)

            if vendor and vendor != "Unknown":
                await conn.execute(
                    """
                    UPDATE assets
                    SET vendor = CASE
                            WHEN vendor IS NULL OR vendor = '' OR vendor = 'Unknown'
                            THEN $2
                            ELSE vendor
                        END,
                        confidence_score = $3
                    WHERE id = $1
                    """,
                    asset_uuid,
                    vendor,
                    confidence,
                )
            else:
                await conn.execute(
                    "UPDATE assets SET confidence_score = $2 WHERE id = $1",
                    asset_uuid,
                    confidence,
                )
