"""Parser for Zeek http.log (TSV format)."""

from typing import Any

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.parsers.base_parser import BaseParser

# http.log #fields:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p trans_depth method host
# uri referrer version user_agent origin request_body_len response_body_len
# status_code status_msg info_code info_msg tags username password proxied
# orig_fuids orig_filenames orig_mime_types resp_fuids resp_filenames resp_mime_types


class HttpParser(BaseParser):
    """Parses Zeek http.log — assets, IPs, http_sessions, user-agent fingerprints."""

    LOG_FILE = "http.log"

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        super().__init__(repo, batch_size)

    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of http.log TSV rows."""
        processed = 0
        failed = 0
        http_rows: list[dict[str, Any]] = []
        fp_rows: list[dict[str, Any]] = []

        pool = self.repo._pool
        async with pool.acquire() as conn:
            async with conn.transaction():
                for record in batch:
                    try:
                        orig_ip = record.get("id.orig_h")
                        if not orig_ip:
                            failed += 1
                            continue

                        ts = self._parse_ts(record.get("ts"))
                        host = record.get("host")
                        uri = record.get("uri")
                        user_agent = record.get("user_agent")
                        method = record.get("method")
                        status_code = _safe_int(record.get("status_code"))

                        asset_id = await self.repo.resolve_asset(conn, orig_ip, ts)
                        await self.repo.upsert_asset_ip(conn, asset_id, orig_ip, ts)

                        http_rows.append({
                            "asset_id": asset_id,
                            "host": host,
                            "uri": uri,
                            "user_agent": user_agent,
                            "method": method,
                            "status_code": status_code,
                            "timestamp": ts,
                        })

                        if user_agent:
                            fp_rows.append({
                                "asset_id": asset_id,
                                "user_agent": user_agent,
                                "timestamp": ts,
                            })
                        processed += 1
                    except Exception:
                        self.logger.exception("Failed to process http record")
                        failed += 1

        if http_rows:
            await self.repo.write_http_sessions(http_rows)
        if fp_rows:
            await self.repo.write_fingerprints(fp_rows)
        return processed, failed


def _safe_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
