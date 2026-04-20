"""Parser for Zeek dhcp.log (TSV format)."""

from typing import Any

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.parsers.base_parser import BaseParser

# dhcp.log schemas observed in this repo:
#
# Old/base:
# ts uids client_addr server_addr mac host_name client_fqdn domain
# requested_addr assigned_addr lease_time client_message server_message
# msg_types duration
#
# Current generated sample logs:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p mac assigned_addr lease_time
# host_name client_fqdn vendor_class


class DhcpParser(BaseParser):
    """Parses Zeek dhcp.log — assets by MAC, hostnames, DHCP vendor fingerprints."""

    LOG_FILE = "dhcp.log"

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        super().__init__(repo, batch_size)

    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of dhcp.log TSV rows."""
        processed = 0
        failed = 0
        hostname_rows: list[dict[str, Any]] = []
        fp_rows: list[dict[str, Any]] = []

        pool = self.repo._pool
        async with pool.acquire() as conn:
            async with conn.transaction():
                for record in batch:
                    try:
                        # Support both the base Zeek schema and the generated sample schema.
                        client_ip = (
                            record.get("client_addr")
                            or record.get("assigned_addr")
                            or record.get("requested_addr")
                        )
                        mac = record.get("mac")

                        # Must have at least a MAC to identify the asset
                        if not mac:
                            failed += 1
                            continue

                        ts = self._parse_ts(record.get("ts"))
                        host_name = record.get("host_name")
                        client_fqdn = record.get("client_fqdn")
                        dhcp_vendor = record.get("vendor_class") or record.get("domain")

                        # MAC is always present here; IP may be None for DISCOVER
                        asset_id = await self.repo.upsert_asset_by_mac(conn, mac, None, ts)

                        if client_ip and client_ip != "0.0.0.0":
                            await self.repo.upsert_asset_ip(conn, asset_id, client_ip, ts)

                        if host_name:
                            hostname_rows.append({
                                "asset_id": asset_id,
                                "hostname": host_name,
                                "source": "dhcp",
                                "timestamp": ts,
                            })

                        if client_fqdn and client_fqdn != host_name:
                            hostname_rows.append({
                                "asset_id": asset_id,
                                "hostname": client_fqdn,
                                "source": "dhcp_fqdn",
                                "timestamp": ts,
                            })

                        if dhcp_vendor:
                            fp_rows.append({
                                "asset_id": asset_id,
                                "dhcp_vendor": dhcp_vendor,
                                "timestamp": ts,
                            })
                        processed += 1
                    except Exception:
                        self.logger.exception("Failed to process dhcp record")
                        failed += 1

        if hostname_rows:
            await self.repo.write_asset_hostnames(hostname_rows)
        if fp_rows:
            await self.repo.write_fingerprints(fp_rows)
        return processed, failed
