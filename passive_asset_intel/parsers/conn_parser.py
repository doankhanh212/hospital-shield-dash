"""Parser for Zeek conn.log (TSV format)."""

from typing import Any

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.parsers.base_parser import BaseParser

# conn.log #fields:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration
# orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes
# history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents ip_proto


class ConnParser(BaseParser):
    """Parses Zeek conn.log — assets, IPs, behaviors, connections."""

    LOG_FILE = "conn.log"

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        super().__init__(repo, batch_size)

    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of conn.log TSV rows."""
        processed = 0
        failed = 0
        conn_rows: list[dict[str, Any]] = []
        behavior_rows: list[dict[str, Any]] = []

        pool = self.repo._pool
        async with pool.acquire() as conn:
            async with conn.transaction():
                for record in batch:
                    try:
                        id_orig = record.get("id.orig_h")
                        id_resp = record.get("id.resp_h")
                        if not id_orig or not id_resp:
                            failed += 1
                            continue

                        ts = self._parse_ts(record.get("ts"))
                        orig_port = _safe_int(record.get("id.orig_p"))
                        resp_port = _safe_int(record.get("id.resp_p"))
                        proto = record.get("proto") or ""
                        service = record.get("service")
                        duration = _safe_float(record.get("duration"))
                        orig_bytes = _safe_int(record.get("orig_bytes"))
                        resp_bytes = _safe_int(record.get("resp_bytes"))

                        src_id = await self.repo.resolve_asset(conn, id_orig, ts)
                        dst_id = await self.repo.resolve_asset(conn, id_resp, ts)
                        await self.repo.upsert_asset_ip(conn, src_id, id_orig, ts)
                        await self.repo.upsert_asset_ip(conn, dst_id, id_resp, ts)

                        conn_rows.append({
                            "src_asset_id": src_id,
                            "dst_asset_id": dst_id,
                            "src_ip": id_orig,
                            "dst_ip": id_resp,
                            "src_port": orig_port,
                            "dst_port": resp_port,
                            "protocol": proto,
                            "service": service,
                            "duration": duration,
                            "bytes_sent": orig_bytes,
                            "bytes_received": resp_bytes,
                            "timestamp": ts,
                        })
                        behavior_rows.append({
                            "asset_id": src_id,
                            "protocol": proto,
                            "port": resp_port,
                            "service": service,
                            "timestamp": ts,
                        })
                        processed += 1
                    except Exception:
                        self.logger.exception("Failed to process conn record")
                        failed += 1

        if conn_rows:
            await self.repo.write_connections(conn_rows)
        if behavior_rows:
            await self.repo.write_behaviors(behavior_rows)
        return processed, failed


def _safe_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return None


def _safe_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None
