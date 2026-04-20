"""Parser for Zeek ssl.log (TSV format)."""

from typing import Any

from passive_asset_intel.db.repository import Repository
from passive_asset_intel.parsers.base_parser import BaseParser

# ssl.log #fields:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve
# server_name resumed last_alert next_protocol established ssl_history
# cert_chain_fuids client_cert_chain_fuids subject issuer client_subject
# client_issuer validation_status ja3 ja3s


class SslParser(BaseParser):
    """Parses Zeek ssl.log — assets, IPs, tls_sessions, JA3 fingerprints."""

    LOG_FILE = "ssl.log"

    def __init__(self, repo: Repository, batch_size: int = 500) -> None:
        super().__init__(repo, batch_size)

    @staticmethod
    def _parse_bool(raw: Any) -> bool | None:
        """Parse Zeek bool fields represented as T/F strings."""
        if raw is None:
            return None
        value = str(raw).strip().lower()
        if value in {"t", "true", "1"}:
            return True
        if value in {"f", "false", "0"}:
            return False
        return None

    async def process_batch(self, batch: list[dict[str, Any]]) -> tuple[int, int]:
        """Process a batch of ssl.log TSV rows."""
        processed = 0
        failed = 0
        tls_rows: list[dict[str, Any]] = []
        fp_rows: list[dict[str, Any]] = []

        pool = self.repo._pool
        async with pool.acquire() as conn:
            async with conn.transaction():
                for record in batch:
                    try:
                        orig_ip = record.get("id.orig_h")
                        resp_ip = record.get("id.resp_h")
                        if not orig_ip:
                            failed += 1
                            continue

                        ts = self._parse_ts(record.get("ts"))
                        server_name = record.get("server_name")
                        version = record.get("version")
                        # ja3/ja3s only present if a JA3 package/script is loaded into Zeek
                        ja3 = record.get("ja3")
                        ja3s = record.get("ja3s")
                        issuer = record.get("issuer")
                        next_protocol = record.get("next_protocol")
                        validation_status = record.get("validation_status")
                        sni_matches_cert = self._parse_bool(record.get("sni_matches_cert"))
                        ssl_history = record.get("ssl_history")

                        # Direction matters: JA3 belongs to the client (id.orig_h),
                        # JA3S to the server (id.resp_h). Mixing them on the same
                        # asset row makes a server look like Android, etc.
                        client_id = await self.repo.resolve_asset(conn, orig_ip, ts)
                        await self.repo.upsert_asset_ip(conn, client_id, orig_ip, ts)

                        server_id = None
                        if resp_ip:
                            server_id = await self.repo.resolve_asset(conn, resp_ip, ts)
                            await self.repo.upsert_asset_ip(conn, server_id, resp_ip, ts)

                        # tls_sessions row stays on the client — it represents the
                        # outbound TLS session (SNI, validation, cert issuer).
                        tls_rows.append({
                            "asset_id": client_id,
                            "ja3": ja3,
                            "ja3s": ja3s,
                            "server_name": server_name,
                            "certificate_issuer": issuer,
                            "version": version,
                            "next_protocol": next_protocol,
                            "validation_status": validation_status,
                            "sni_matches_cert": sni_matches_cert,
                            "ssl_history": ssl_history,
                            "timestamp": ts,
                        })

                        # Fingerprints split by direction.
                        if ja3:
                            fp_rows.append({
                                "asset_id": client_id,
                                "ja3": ja3,
                                "ja3s": None,
                                "timestamp": ts,
                            })
                        if ja3s and server_id:
                            fp_rows.append({
                                "asset_id": server_id,
                                "ja3": None,
                                "ja3s": ja3s,
                                "timestamp": ts,
                            })
                        processed += 1
                    except Exception:
                        self.logger.exception("Failed to process ssl record")
                        failed += 1

        if tls_rows:
            await self.repo.write_tls_sessions(tls_rows)
        if fp_rows:
            await self.repo.write_fingerprints(fp_rows)
        return processed, failed
