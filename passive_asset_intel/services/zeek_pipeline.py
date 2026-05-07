"""Real-time Zeek log pipeline — anomaly detection + XDR persistence.

Tails /usr/local/zeek/logs/current/{conn,dns,ssl}.log, aggregates per-IP
activity in 60-second windows, detects anomalies, persists them to PostgreSQL
via the XDR storage layer, and triggers the correlation engine.

Production entrypoint (with DB)::
    python -m passive_asset_intel.services.zeek_pipeline

Standalone dry-run (no DB, prints to stdout)::
    python -m passive_asset_intel.services.zeek_pipeline --dry-run
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import asyncpg

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

ZEEK_LOG_DIR    = Path("/usr/local/zeek/logs/current")
WINDOW_SECONDS  = 30
POLL_INTERVAL   = 1.0   # seconds between tail polls


# ── Log tailer ───────────────────────────────────────────────────────────────

@dataclass
class _FileState:
    path:  Path
    inode: int
    offset: int
    fh: object  # open file handle


class LogTailer:
    """Tail-follows multiple log files, yielding (log_type, parsed_dict).

    Handles:
    - New lines appended since last poll
    - Log rotation (inode change → reopen from offset 0)
    - File temporarily missing (zeekctl rotation gap)
    """

    def __init__(self, files: dict[str, Path]) -> None:
        self._files  = files
        self._states: dict[str, _FileState] = {}
        self._init_all()

    def _init_all(self) -> None:
        for log_type, path in self._files.items():
            self._open_at_end(log_type, path)

    def _open_at_end(self, log_type: str, path: Path) -> None:
        try:
            st = os.stat(path)
            fh = open(path, "r", errors="replace")
            fh.seek(0, 2)
            self._states[log_type] = _FileState(
                path=path, inode=st.st_ino, offset=fh.tell(), fh=fh
            )
        except OSError:
            self._states.pop(log_type, None)

    def _reopen_from_start(self, log_type: str, path: Path) -> None:
        old = self._states.pop(log_type, None)
        if old:
            try:
                old.fh.close()
            except OSError:
                pass
        try:
            st = os.stat(path)
            fh = open(path, "r", errors="replace")
            self._states[log_type] = _FileState(
                path=path, inode=st.st_ino, offset=0, fh=fh
            )
        except OSError:
            pass

    def poll(self) -> Iterator[tuple[str, dict]]:
        """Yield all new (log_type, record) pairs accumulated since last poll."""
        for log_type, path in self._files.items():
            state = self._states.get(log_type)

            if state is None:
                self._open_at_end(log_type, path)
                continue

            try:
                current_inode = os.stat(path).st_ino
            except OSError:
                continue

            if current_inode != state.inode:
                self._reopen_from_start(log_type, path)
                state = self._states.get(log_type)
                if state is None:
                    continue

            state.fh.seek(state.offset)
            for raw in state.fh:
                raw = raw.rstrip("\n")
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                yield log_type, record
            state.offset = state.fh.tell()

    def close(self) -> None:
        for state in self._states.values():
            try:
                state.fh.close()
            except OSError:
                pass


# ── Feature extraction ───────────────────────────────────────────────────────

def extract_conn(r: dict) -> dict | None:
    src  = r.get("id.orig_h")
    dst  = r.get("id.resp_h")
    port = r.get("id.resp_p")
    if src is None or dst is None or port is None:
        return None
    return {
        "src_ip":    src,
        "dest_ip":   dst,
        "dest_port": int(port),
        "bytes_out": int(r.get("orig_bytes") or 0),
        "bytes_in":  int(r.get("resp_bytes") or 0),
    }


def extract_dns(r: dict) -> dict | None:
    src    = r.get("id.orig_h")
    domain = r.get("query")
    if src is None or not domain:
        return None
    return {"src_ip": src, "domain": domain}


def extract_ssl(r: dict) -> dict | None:
    src = r.get("id.orig_h")
    ja3 = r.get("ja3")
    if src is None or not ja3:
        return None
    return {"src_ip": src, "ja3": ja3}


_EXTRACTORS = {
    "conn": extract_conn,
    "dns":  extract_dns,
    "ssl":  extract_ssl,
}


# ── Activity window ──────────────────────────────────────────────────────────

@dataclass
class _IPWindow:
    conn_count:     int = 0
    unique_ports:   set = field(default_factory=set)
    bytes_out:      int = 0
    bytes_in:       int = 0
    dns_count:      int = 0
    unique_domains: set = field(default_factory=set)
    ja3_hashes:     set = field(default_factory=set)


class WindowAggregator:
    """Accumulates per-IP metrics; flushes and resets every window_seconds.

    The flushed snapshot carries both the aggregated scalars (counts, sums)
    and the raw observation lists so the profile engine can update its
    frequency maps and the detector can evaluate per-item rules (rare_ja3,
    rare_domain).
    """

    def __init__(self, window: int = WINDOW_SECONDS) -> None:
        self._window  = window
        self._start   = time.monotonic()
        self._windows: dict[str, _IPWindow] = defaultdict(_IPWindow)

    def ingest(self, log_type: str, feat: dict) -> None:
        ip = feat["src_ip"]
        w  = self._windows[ip]
        if log_type == "conn":
            w.conn_count += 1
            w.unique_ports.add(feat["dest_port"])
            w.bytes_out += feat["bytes_out"]
            w.bytes_in  += feat["bytes_in"]
        elif log_type == "dns":
            w.dns_count += 1
            w.unique_domains.add(feat["domain"])
        elif log_type == "ssl":
            w.ja3_hashes.add(feat["ja3"])

    def is_ready(self) -> bool:
        return (time.monotonic() - self._start) >= self._window

    def flush(self) -> list[dict]:
        snapshots = [
            {
                "asset_id":       ip,
                "conn_count":     w.conn_count,
                "unique_ports":   len(w.unique_ports),
                "bytes_out":      w.bytes_out,
                "bytes_in":       w.bytes_in,
                "dns_count":      w.dns_count,
                "unique_domains": len(w.unique_domains),
                "ja3_count":      len(w.ja3_hashes),
                # Raw observations (used by profile + per-item detection rules)
                "_ports":   sorted(w.unique_ports),
                "_domains": sorted(w.unique_domains),
                "_ja3":     sorted(w.ja3_hashes),
            }
            for ip, w in self._windows.items()
        ]
        self._windows.clear()
        self._start = time.monotonic()
        return snapshots


# ── Synchronous poll helper (safe for asyncio.to_thread) ─────────────────────

def _poll_sync(tailer: LogTailer) -> list[tuple[str, dict]]:
    results: list[tuple[str, dict]] = []
    for log_type, record in tailer.poll():
        extractor = _EXTRACTORS.get(log_type)
        if extractor is None:
            continue
        feat = extractor(record)
        if feat is not None:
            results.append((log_type, feat))
    return results


# ── Async production loop ────────────────────────────────────────────────────

async def run_async(pool: asyncpg.Pool) -> None:
    """Production loop — full XDR flow per activity window.

    For every ``WINDOW_SECONDS`` flush:
        1. compute baseline + run hybrid detection
        2. enrich each alert with VT + AbuseIPDB intel (cached, async)
        3. score the alert and derive severity
        4. upsert into xdr_anomalies
        5. run correlation engine
        6. update the asset profile (so future windows know normal behaviour)
        7. refresh the asset registry (xdr_assets)

    File I/O runs in a ThreadPoolExecutor via asyncio.to_thread so the event
    loop is never blocked.  All DB writes and intel calls are fully async.
    """
    from passive_asset_intel.xdr.correlation  import correlate
    from passive_asset_intel.xdr.detection    import detect as detect_with_baseline
    from passive_asset_intel.xdr.fingerprint  import fingerprint as fingerprint_asset
    from passive_asset_intel.xdr.nac          import decide as nac_decide
    from passive_asset_intel.xdr.profile      import compute_baseline, update_profile
    from passive_asset_intel.xdr.response     import handle_response
    from passive_asset_intel.xdr.rogue        import evaluate as evaluate_rogue
    from passive_asset_intel.xdr.scoring      import enrich_alert
    from passive_asset_intel.xdr.storage      import upsert_anomaly, upsert_asset
    from passive_asset_intel.xdr.threat_intel import enrich as intel_enrich

    log_files = {
        "conn": ZEEK_LOG_DIR / "conn.log",
        "dns":  ZEEK_LOG_DIR / "dns.log",
        "ssl":  ZEEK_LOG_DIR / "ssl.log",
    }

    tailer     = LogTailer(log_files)
    aggregator = WindowAggregator(WINDOW_SECONDS)

    logger.info(
        "XDR pipeline started",
        extra={"log_dir": str(ZEEK_LOG_DIR), "window_s": WINDOW_SECONDS},
    )

    try:
        while True:
            events = await asyncio.to_thread(_poll_sync, tailer)

            for log_type, feat in events:
                aggregator.ingest(log_type, feat)

            if aggregator.is_ready():
                for activity in aggregator.flush():
                    await _process_window(
                        pool, activity,
                        compute_baseline   = compute_baseline,
                        detect             = detect_with_baseline,
                        intel_enrich       = intel_enrich,
                        enrich_alert       = enrich_alert,
                        upsert_anomaly     = upsert_anomaly,
                        correlate          = correlate,
                        update_profile     = update_profile,
                        upsert_asset       = upsert_asset,
                        handle_response    = handle_response,
                        fingerprint_asset  = fingerprint_asset,
                        evaluate_rogue     = evaluate_rogue,
                        nac_decide         = nac_decide,
                    )

            await asyncio.sleep(POLL_INTERVAL)

    except asyncio.CancelledError:
        logger.info("XDR pipeline cancelled — shutting down")
    finally:
        tailer.close()


async def _fetch_asset_meta(pool: asyncpg.Pool, asset_ip: str) -> dict:
    """Pull the latest known MAC / vendor / hostname for an IP.  Empty dict
    when the IP isn't linked yet (e.g. external attacker)."""
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT a.mac_address AS mac,
                       a.vendor      AS vendor,
                       (SELECT hostname FROM asset_hostnames
                         WHERE asset_id = a.id
                         ORDER BY last_seen DESC LIMIT 1) AS hostname
                FROM   asset_ips ai
                JOIN   assets    a  ON a.id = ai.asset_id
                WHERE  ai.ip_address = $1::inet
                ORDER BY ai.is_primary DESC, ai.last_seen DESC
                LIMIT  1
                """,
                asset_ip,
            )
        return dict(row) if row else {}
    except Exception:
        return {}


async def _process_window(
    pool: asyncpg.Pool,
    activity: dict,
    *,
    compute_baseline,
    detect,
    intel_enrich,
    enrich_alert,
    upsert_anomaly,
    correlate,
    update_profile,
    upsert_asset,
    handle_response,
    fingerprint_asset = None,
    evaluate_rogue    = None,
    nac_decide        = None,
) -> None:
    """Single-window pipeline: baseline → detect → enrich → score → persist."""
    asset_id = activity["asset_id"]

    try:
        # 1. Best-effort asset registry refresh (non-fatal).
        try:
            await upsert_asset(pool, asset_id)
        except Exception:
            logger.exception("xdr_assets upsert failed", extra={"asset": asset_id})

        # 2. Load baseline + run hybrid detection.
        baseline = await compute_baseline(pool, asset_id)
        alerts = detect(
            activity,
            baseline,
            observed_domains = activity.get("_domains", []),
            observed_ja3     = activity.get("_ja3",     []),
        )

        # 2b. Compute a passive fingerprint hint for this asset window.
        fp_hint = None
        asset_meta = await _fetch_asset_meta(pool, asset_id)
        if fingerprint_asset is not None:
            fp_hint = fingerprint_asset(
                mac        = asset_meta.get("mac"),
                vendor     = asset_meta.get("vendor"),
                ports_used = activity.get("_ports", []),
                dns_count  = activity["dns_count"],
                ja3_count  = activity["ja3_count"],
                hostname   = asset_meta.get("hostname"),
            )

        # 2c. Rogue device check (additive — adds to alerts list).
        if evaluate_rogue is not None and asset_meta.get("mac"):
            rogue = await evaluate_rogue(
                pool,
                asset_ip = asset_id,
                mac      = asset_meta["mac"],
                vendor   = asset_meta.get("vendor"),
                fp       = fp_hint,
            )
            if rogue is not None:
                alerts.append(rogue)

        # 3-5. For each alert: enrich, score, persist, correlate.
        for alert in alerts:
            try:
                deviation = float(alert.pop("deviation", 1.0))
                intel = await intel_enrich(pool, asset_id)
                enrich_alert(alert, intel, deviation=deviation)

                # Attach NAC recommendation + fingerprint hint to the evidence
                if fp_hint is not None:
                    alert.setdefault("evidence", {})["fingerprint"] = fp_hint.to_dict()
                if nac_decide is not None:
                    alert.setdefault("evidence", {})["nac"] = nac_decide(
                        anomaly_type = alert["type"],
                        score        = float(alert.get("score", 0.0)),
                        device_type  = (fp_hint.device_type if fp_hint else None),
                        ports_used   = activity.get("_ports", []),
                    )

                saved = await upsert_anomaly(pool, alert)
                await correlate(pool, asset_id)
                # Future-ready response hook (today: log only)
                try:
                    await handle_response(saved)
                except Exception:
                    logger.exception(
                        "Response hook failed",
                        extra={"asset": asset_id, "type": alert.get("type")},
                    )
            except Exception:
                logger.exception(
                    "XDR anomaly pipeline failed",
                    extra={"asset": asset_id, "type": alert.get("type")},
                )

        # 6. Update profile *after* detection so the current window does not
        #    immediately become its own baseline.
        await update_profile(
            pool, asset_id, activity,
            ports   = activity.get("_ports",   []),
            domains = activity.get("_domains", []),
            ja3s    = activity.get("_ja3",     []),
        )
    except Exception:
        logger.exception("XDR window processing failed", extra={"asset": asset_id})


# ── Dry-run loop (no DB, stdout only) ────────────────────────────────────────

def run() -> None:
    """Standalone dry-run — prints raw activity windows to stdout, no DB.

    Useful for sanity-checking the tail/parse path without a database.  Full
    XDR detection (which needs baselines + intel) is only available via the
    async DB-backed path.
    """
    from passive_asset_intel.xdr.detection import detect as detect_with_baseline
    from passive_asset_intel.xdr.profile   import Baseline

    log_files = {
        "conn": ZEEK_LOG_DIR / "conn.log",
        "dns":  ZEEK_LOG_DIR / "dns.log",
        "ssl":  ZEEK_LOG_DIR / "ssl.log",
    }

    tailer     = LogTailer(log_files)
    aggregator = WindowAggregator(WINDOW_SECONDS)

    print(
        f"[zeek_pipeline] dry-run — tailing {ZEEK_LOG_DIR}, "
        f"window={WINDOW_SECONDS}s (cold-baseline rules only)",
        flush=True,
    )

    try:
        while True:
            for log_type, record in tailer.poll():
                extractor = _EXTRACTORS.get(log_type)
                if extractor is None:
                    continue
                feat = extractor(record)
                if feat is not None:
                    aggregator.ingest(log_type, feat)

            if aggregator.is_ready():
                for activity in aggregator.flush():
                    cold = Baseline(asset_id=activity["asset_id"])
                    alerts = detect_with_baseline(
                        activity, cold,
                        observed_domains = activity.get("_domains", []),
                        observed_ja3     = activity.get("_ja3",     []),
                    )
                    for alert in alerts:
                        alert["ts"] = datetime.now(tz=timezone.utc).isoformat()
                        print(json.dumps(alert, indent=2, default=str), flush=True)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[zeek_pipeline] stopped.", flush=True)
    finally:
        tailer.close()


# ── Entrypoint ───────────────────────────────────────────────────────────────

async def _main_async() -> None:
    from passive_asset_intel.utils.config import load_config
    config = load_config()
    pool = await asyncpg.create_pool(
        host=config.db_host,
        port=config.db_port,
        database=config.db_name,
        user=config.db_user,
        password=config.db_password,
        min_size=config.db_pool_min,
        max_size=config.db_pool_max,
        statement_cache_size=0,
    )
    try:
        await run_async(pool)
    finally:
        await pool.close()


if __name__ == "__main__":
    if "--dry-run" in sys.argv:
        run()
    else:
        asyncio.run(_main_async())
