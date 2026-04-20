"""Parser for Zeek dns.log (TSV format)."""

from typing import Any

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.parsers.base_parser import BaseParser

# dns.log #fields:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt
# query qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA
# Z rejected answers TTLs rejected


class DnsParser(BaseParser):
    """Parses Zeek dns.log — assets, IPs, dns_queries."""

    LOG_FILE = "dns.log"

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        super().__init__(repo, batch_size)

    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of dns.log TSV rows."""
        processed = 0
        failed = 0
        dns_rows: list[dict[str, Any]] = []

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
                        query = record.get("query") or ""
                        qtype = record.get("qtype_name")

                        # answers is a comma-separated list in TSV
                        raw_answers = record.get("answers")
                        answer_str = raw_answers if raw_answers else None

                        asset_id = await self.repo.resolve_asset(conn, orig_ip, ts)
                        await self.repo.upsert_asset_ip(conn, asset_id, orig_ip, ts)

                        dns_rows.append({
                            "asset_id": asset_id,
                            "query": query,
                            "answer": answer_str,
                            "query_type": qtype,
                            "timestamp": ts,
                        })
                        processed += 1
                    except Exception:
                        self.logger.exception("Failed to process dns record")
                        failed += 1

        if dns_rows:
            await self.repo.write_dns_queries(dns_rows)
        return processed, failed
