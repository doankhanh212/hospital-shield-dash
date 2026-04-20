"""Zeek TSV file writer — produces exact Zeek 8.x header format."""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, List, Optional


def _fmt_ts(ts: float) -> str:
    """Format a Unix timestamp with 6 decimal places."""
    return f"{ts:.6f}"


def _val(v, unset: str = "-") -> str:
    """Convert a value to its TSV string representation.

    - None → unset marker ("-")
    - bool → "T" / "F"
    - everything else → str(v)
    """
    if v is None:
        return unset
    if isinstance(v, bool):
        return "T" if v else "F"
    return str(v)


class TsvWriter:
    """Write Zeek-format TSV log files (dhcp, conn, dns, http, ssl)."""

    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._handles: dict[str, IO[str]] = {}
        self._open_all()

    # ── internal setup ───────────────────────────────────────────────

    def _open_all(self) -> None:
        self._handles["dhcp"] = self._open_file("dhcp.log", _DHCP_HEADER)
        self._handles["conn"] = self._open_file("conn.log", _CONN_HEADER)
        self._handles["dns"] = self._open_file("dns.log", _DNS_HEADER)
        self._handles["http"] = self._open_file("http.log", _HTTP_HEADER)
        self._handles["ssl"] = self._open_file("ssl.log", _SSL_HEADER)

    def _open_file(self, name: str, header: str) -> IO[str]:
        fh = open(self.output_dir / name, "w", encoding="utf-8", newline="\n")
        fh.write(header)
        return fh

    def _write_row(self, log_type: str, fields: List[str]) -> None:
        self._handles[log_type].write("\t".join(fields) + "\n")

    # ── public writers ───────────────────────────────────────────────

    def write_dhcp(
        self,
        ts: float,
        uid: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        mac: str,
        assigned_ip: str,
        lease_time: float,
        hostname: str,
        client_fqdn: str,
        vendor_class: str,
    ) -> None:
        self._write_row("dhcp", [
            _fmt_ts(ts),
            uid,
            src_ip,
            str(src_port),
            dst_ip,
            str(dst_port),
            mac,
            assigned_ip,
            f"{lease_time:.6f}",
            _val(hostname),
            _val(client_fqdn),
            _val(vendor_class),
        ])

    def write_conn(
        self,
        ts: float,
        uid: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        service: str,
        duration: float,
        orig_bytes: int,
        resp_bytes: int,
        conn_state: str,
    ) -> None:
        # local_orig / local_resp always T for internal traffic
        local_orig = "T"
        local_resp = "T"
        missed_bytes = "0"

        if conn_state == "SF":
            history = "ShADadFf"
        elif conn_state == "S0":
            history = "S"
        else:
            history = "ShADaR"  # RSTO

        # Approximate packet counts from bytes
        orig_pkts = max(1, orig_bytes // 1460 + 1) if orig_bytes > 0 else 1
        resp_pkts = max(1, resp_bytes // 1460 + 1) if resp_bytes > 0 else 0
        orig_ip_bytes = orig_bytes + orig_pkts * 40 if orig_bytes > 0 else 40
        resp_ip_bytes = resp_bytes + resp_pkts * 40 if resp_bytes > 0 else 0

        self._write_row("conn", [
            _fmt_ts(ts),
            uid,
            src_ip,
            str(src_port),
            dst_ip,
            str(dst_port),
            proto,
            _val(service),
            f"{duration:.6f}" if duration > 0 else "-",
            str(orig_bytes) if orig_bytes > 0 else "0",
            str(resp_bytes) if resp_bytes > 0 else "0",
            conn_state,
            local_orig,
            local_resp,
            missed_bytes,
            history,
            str(orig_pkts),
            str(orig_ip_bytes),
            str(resp_pkts),
            str(resp_ip_bytes),
        ])

    def write_dns(
        self,
        ts: float,
        uid: str,
        src_ip: str,
        query: str,
        answer_ip: str,
        dns_server: str = "10.0.0.1",
        src_port: int = 50000,
    ) -> None:
        self._write_row("dns", [
            _fmt_ts(ts),
            uid,
            src_ip,
            str(src_port),
            dns_server,
            "53",
            "udp",
            "0",              # trans_id
            "0.001000",       # rtt
            query,
            "1",              # qclass
            "C_INTERNET",     # qclass_name
            "1",              # qtype
            "A",              # qtype_name
            "0",              # rcode
            "NOERROR",        # rcode_name
            "F",              # AA
            "F",              # TC
            "T",              # RD
            "T",              # RA
            "0",              # Z
            answer_ip,        # answers
            "300.000000",     # TTLs
            "F",              # rejected
        ])

    def write_http(
        self,
        ts: float,
        uid: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        method: str,
        host: str,
        uri: str,
        user_agent: str,
        status_code: int,
        response_body_len: int = 5000,
    ) -> None:
        self._write_row("http", [
            _fmt_ts(ts),
            uid,
            src_ip,
            str(src_port),
            dst_ip,
            str(dst_port),
            "1",              # trans_depth
            method,
            host,
            uri,
            "-",              # referrer
            "1.1",            # version
            _val(user_agent),
            "-",              # origin
            "0",              # request_body_len
            str(response_body_len),
            str(status_code),
            "OK" if status_code == 200 else "Not Found" if status_code == 404 else "-",
            "-",              # info_code
            "-",              # info_msg
            "(empty)",        # tags
            "-",              # username
            "-",              # password
            "(empty)",        # proxied
            "-",              # orig_fuids
            "-",              # orig_filenames
            "-",              # orig_mime_types
            "-",              # resp_fuids
            "-",              # resp_filenames
            "-",              # resp_mime_types
        ])

    def write_ssl(
        self,
        ts: float,
        uid: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        server_name: str,
    ) -> None:
        self._write_row("ssl", [
            _fmt_ts(ts),
            uid,
            src_ip,
            str(src_port),
            dst_ip,
            str(dst_port),
            "TLSv13",                      # version
            "TLS_AES_256_GCM_SHA384",      # cipher
            "x25519",                       # curve
            server_name,
            "F",                            # resumed
            "-",                            # last_alert
            "h2",                           # next_protocol
            "T",                            # established
            "-",                            # ssl_history
            "-",                            # validation_status
            "-",                            # sni_matches_cert
            "-",                            # ja3
            "-",                            # ja3s
        ])

    def close(self) -> None:
        """Flush and close all file handles."""
        for fh in self._handles.values():
            fh.flush()
            fh.close()
        self._handles.clear()

    @property
    def files_written(self) -> List[str]:
        return [
            str(self.output_dir / "dhcp.log"),
            str(self.output_dir / "conn.log"),
            str(self.output_dir / "dns.log"),
            str(self.output_dir / "http.log"),
            str(self.output_dir / "ssl.log"),
        ]


# ── Zeek TSV headers (exact format) ─────────────────────────────────

_DHCP_HEADER = """\
#separator \x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdhcp
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmac\tassigned_addr\tlease_time\thost_name\tclient_fqdn\tvendor_class
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\taddr\tinterval\tstring\tstring\tstring
"""

_CONN_HEADER = """\
#separator \x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount
"""

_DNS_HEADER = """\
#separator \x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool
"""

_HTTP_HEADER = """\
#separator \x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\thttp
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\ttrans_depth\tmethod\thost\turi\treferrer\tversion\tuser_agent\torigin\trequest_body_len\tresponse_body_len\tstatus_code\tstatus_msg\tinfo_code\tinfo_msg\ttags\tusername\tpassword\tproxied\torig_fuids\torig_filenames\torig_mime_types\tresp_fuids\tresp_filenames\tresp_mime_types
#types\ttime\tstring\taddr\tport\taddr\tport\tcount\tstring\tstring\tstring\tstring\tstring\tstring\tstring\tcount\tcount\tcount\tstring\tcount\tstring\tset[enum]\tstring\tstring\tset[string]\tvector[string]\tvector[string]\tvector[string]\tvector[string]\tvector[string]\tvector[string]
"""

_SSL_HEADER = """\
#separator \x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tssl
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished\tssl_history\tvalidation_status\tsni_matches_cert\tja3\tja3s
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tstring\tstring\tbool\tstring\tstring\tbool\tstring\tstring
"""
