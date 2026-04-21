"""Seed mock hospital-network data for demos.

Generates a realistic-looking inventory without needing a live Zeek sensor:
    * ~60 assets across the configured LOCAL_SUBNETS
    * Device-type inference results (IoMT, Server, Workstation, ...)
    * Hostnames, vendors, behaviors (ports/protocols)
    * A pool of real-world CVEs, randomly attached to vulnerable assets
    * A handful of aggregated connections between assets

Usage inside the app container::

    python -m passive_asset_intel.scripts.seed_mock_data

Idempotent: existing rows with the same MAC / CVE are kept, and the script
adds more only up to its target count.  Safe to re-run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg

from passive_asset_intel.utils.config import load_config


# ── Templates ────────────────────────────────────────────────────────────────

DEVICE_POOL: list[dict] = [
    # device_type, behavior_type, vendor pool, hostname prefix, ports
    {"device_type": "IoMT",        "behavior_type": "Medical Device",
     "vendors": ["GE Healthcare", "Philips", "Siemens Healthineers", "Mindray"],
     "hostname": ["mri", "ct-scanner", "ultrasound", "ecg", "ventilator"],
     "ports": [(80, "http"), (443, "https"), (104, "dicom"), (11112, "dicom")]},

    {"device_type": "Server",      "behavior_type": "Backend Service",
     "vendors": ["Dell", "HPE", "Supermicro", "Lenovo"],
     "hostname": ["app", "db", "api", "erp", "his", "pacs"],
     "ports": [(22, "ssh"), (443, "https"), (5432, "postgres"), (3306, "mysql"), (6379, "redis")]},

    {"device_type": "Workstation", "behavior_type": "User Browsing",
     "vendors": ["Dell", "HP", "Lenovo"],
     "hostname": ["ws-nurse", "ws-admin", "ws-reception", "ws-doctor", "ws-lab"],
     "ports": [(445, "smb"), (139, "netbios"), (3389, "rdp")]},

    {"device_type": "IoT",         "behavior_type": "Embedded Device",
     "vendors": ["Axis", "Hikvision", "Honeywell", "Schneider Electric"],
     "hostname": ["bms", "hvac", "badge-reader", "printer-lobby"],
     "ports": [(80, "http"), (443, "https"), (1883, "mqtt")]},

    {"device_type": "IP Camera",   "behavior_type": "Embedded Device",
     "vendors": ["Hikvision", "Dahua", "Axis", "Bosch"],
     "hostname": ["cam-entrance", "cam-icu", "cam-pharmacy", "cam-lobby"],
     "ports": [(80, "http"), (554, "rtsp"), (8000, "http")]},

    {"device_type": "Network",     "behavior_type": "Backend Service",
     "vendors": ["Cisco", "Juniper", "Aruba", "MikroTik"],
     "hostname": ["sw-core", "sw-access", "fw-edge", "ap-ward"],
     "ports": [(22, "ssh"), (161, "snmp"), (443, "https")]},

    {"device_type": "Printer",     "behavior_type": "Embedded Device",
     "vendors": ["HP", "Canon", "Xerox", "Brother"],
     "hostname": ["printer-ward", "mfp-reception", "printer-lab"],
     "ports": [(9100, "jetdirect"), (631, "ipp"), (80, "http")]},
]


# Curated real CVEs that feel plausible for a hospital inventory.
CVE_POOL: list[dict] = [
    # id, score, severity, description
    {"cve": "CVE-2019-11510", "score": 10.0, "severity": "critical",
     "desc": "Pulse Secure Pulse Connect Secure arbitrary file read via path traversal"},
    {"cve": "CVE-2021-44228", "score": 10.0, "severity": "critical",
     "desc": "Apache Log4j2 JNDI remote code execution (Log4Shell)"},
    {"cve": "CVE-2020-1472",  "score": 10.0, "severity": "critical",
     "desc": "Netlogon elevation of privilege (Zerologon)"},
    {"cve": "CVE-2017-0144",  "score": 8.1,  "severity": "high",
     "desc": "Microsoft SMBv1 remote code execution (EternalBlue / WannaCry vector)"},
    {"cve": "CVE-2019-0708",  "score": 9.8,  "severity": "critical",
     "desc": "Microsoft RDP remote code execution (BlueKeep)"},
    {"cve": "CVE-2022-22965", "score": 9.8,  "severity": "critical",
     "desc": "Spring Framework RCE via data binding (Spring4Shell)"},
    {"cve": "CVE-2022-30190", "score": 7.8,  "severity": "high",
     "desc": "Microsoft Support Diagnostic Tool remote code execution (Follina)"},
    {"cve": "CVE-2021-34527", "score": 8.8,  "severity": "high",
     "desc": "Windows Print Spooler remote code execution (PrintNightmare)"},
    {"cve": "CVE-2020-0796",  "score": 10.0, "severity": "critical",
     "desc": "Microsoft SMBv3 compression remote code execution (SMBGhost)"},
    {"cve": "CVE-2021-26855", "score": 9.1,  "severity": "critical",
     "desc": "Microsoft Exchange Server SSRF (ProxyLogon)"},
    {"cve": "CVE-2023-23397", "score": 9.8,  "severity": "critical",
     "desc": "Microsoft Outlook elevation of privilege via crafted message"},
    {"cve": "CVE-2018-13379", "score": 9.8,  "severity": "critical",
     "desc": "Fortinet FortiOS SSL VPN pre-auth arbitrary file read"},
    {"cve": "CVE-2022-26134", "score": 9.8,  "severity": "critical",
     "desc": "Atlassian Confluence OGNL injection remote code execution"},
    {"cve": "CVE-2021-41773", "score": 7.5,  "severity": "high",
     "desc": "Apache HTTP Server 2.4.49 path traversal"},
    {"cve": "CVE-2020-11896", "score": 10.0, "severity": "critical",
     "desc": "Treck TCP/IP stack IPv4 tunneling remote code execution (Ripple20)"},
    {"cve": "CVE-2023-0669",  "score": 7.2,  "severity": "high",
     "desc": "Fortra GoAnywhere MFT unsafe deserialization"},
    {"cve": "CVE-2021-21972", "score": 9.8,  "severity": "critical",
     "desc": "VMware vCenter Server unauthenticated RCE in vSphere Client"},
    {"cve": "CVE-2019-19781", "score": 9.8,  "severity": "critical",
     "desc": "Citrix ADC / Gateway path traversal leading to RCE"},
    {"cve": "CVE-2022-1388",  "score": 9.8,  "severity": "critical",
     "desc": "F5 BIG-IP iControl REST authentication bypass"},
    {"cve": "CVE-2017-5638",  "score": 10.0, "severity": "critical",
     "desc": "Apache Struts 2 Jakarta Multipart parser RCE"},
    # Some lower-severity entries for distribution shape
    {"cve": "CVE-2020-13942", "score": 5.3,  "severity": "medium",
     "desc": "Apache Unomi information disclosure via crafted request"},
    {"cve": "CVE-2019-12815", "score": 5.0,  "severity": "medium",
     "desc": "ProFTPD mod_copy arbitrary file copy"},
    {"cve": "CVE-2018-15473", "score": 5.3,  "severity": "medium",
     "desc": "OpenSSH user enumeration via malformed auth request"},
    {"cve": "CVE-2015-0235",  "score": 3.7,  "severity": "low",
     "desc": "glibc gethostbyname buffer overflow (GHOST) — mitigated on most modern systems"},
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _pick_host_ips(cidrs: list[str], count: int) -> list[str]:
    """Pick ``count`` distinct host IPs spread across the given CIDRs."""
    out: set[str] = set()
    networks = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.prefixlen >= 31:  # too small to host usable addresses
            continue
        networks.append(net)
    if not networks:
        return []

    guard = 0
    while len(out) < count and guard < count * 20:
        guard += 1
        net = random.choice(networks)
        hosts = list(net.hosts())
        if not hosts:
            continue
        ip = random.choice(hosts[: max(1, min(len(hosts), 250))])
        out.add(str(ip))
    return list(out)


def _mac_for(seed: int) -> str:
    rng = random.Random(seed)
    parts = [rng.randint(0, 255) for _ in range(5)]
    # OUI pool — just a few vendor OUIs for realism
    oui = rng.choice(["8c:10:1f", "00:1e:67", "00:50:56", "b8:27:eb", "f4:39:09"])
    return f"{oui}:" + ":".join(f"{p:02x}" for p in parts)


# ── Main seeding logic ──────────────────────────────────────────────────────

async def seed(target_assets: int = 60) -> None:
    cfg = load_config()
    subnets = cfg.local_subnets_list
    if not subnets:
        print("ERROR: LOCAL_SUBNETS not configured", file=sys.stderr)
        sys.exit(2)

    conn = await asyncpg.connect(
        host=cfg.db_host, port=cfg.db_port, database=cfg.db_name,
        user=cfg.db_user, password=cfg.db_password,
    )
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rng = random.Random(42)  # stable demo output

        # 1) Seed CVE catalog
        for v in CVE_POOL:
            await conn.execute(
                """
                INSERT INTO vulnerabilities (cve_id, cvss_score, severity, description)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (cve_id) DO UPDATE
                   SET cvss_score  = EXCLUDED.cvss_score,
                       severity    = EXCLUDED.severity,
                       description = EXCLUDED.description
                """,
                v["cve"], v["score"], v["severity"], v["desc"],
            )
        cve_rows = await conn.fetch("SELECT id, cvss_score FROM vulnerabilities")
        cve_ids = [r["id"] for r in cve_rows]

        # 2) How many assets do we already have?
        existing_assets = await conn.fetchval(
            """
            SELECT COUNT(*) FROM assets a
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            """,
            subnets,
        ) or 0
        to_create = max(0, target_assets - int(existing_assets))
        print(f"Existing local assets: {existing_assets}. Creating {to_create} more.")

        # 3) Pick IPs for the new assets
        ips = _pick_host_ips(subnets, to_create)
        if len(ips) < to_create:
            print(f"WARN: could only pick {len(ips)} unique IPs from {subnets}")

        # 4) Create assets
        for i, ip in enumerate(ips):
            tmpl = rng.choice(DEVICE_POOL)
            mac = _mac_for(hash((ip, i)) & 0xFFFFFFFF)
            vendor = rng.choice(tmpl["vendors"])
            hostname = f"{rng.choice(tmpl['hostname'])}-{rng.randint(1, 99):02d}"
            asset_id = uuid.uuid4()
            confidence = round(rng.uniform(0.55, 0.94), 2)
            last_seen = now - timedelta(minutes=rng.randint(0, 60 * 24))
            first_seen = last_seen - timedelta(days=rng.randint(1, 30))

            async with conn.transaction():
                # assets row
                await conn.execute(
                    """
                    INSERT INTO assets (id, mac_address, vendor, first_seen, last_seen,
                                        asset_status, confidence_score)
                    VALUES ($1, $2, $3, $4, $5, 'active', $6)
                    ON CONFLICT (mac_address) DO NOTHING
                    """,
                    asset_id, mac, vendor, first_seen, last_seen, confidence,
                )
                # If the MAC collided, skip the rest of this iteration
                real_id = await conn.fetchval(
                    "SELECT id FROM assets WHERE mac_address = $1", mac,
                )
                if real_id is None:
                    continue
                asset_id = real_id

                # primary IP
                await conn.execute(
                    """
                    INSERT INTO asset_ips (id, asset_id, ip_address, first_seen, last_seen, is_primary)
                    VALUES ($1, $2, $3::inet, $4, $5, true)
                    ON CONFLICT (asset_id, ip_address) DO NOTHING
                    """,
                    uuid.uuid4(), asset_id, ip, first_seen, last_seen,
                )

                # hostname
                await conn.execute(
                    """
                    INSERT INTO asset_hostnames (id, asset_id, hostname, source, first_seen, last_seen)
                    VALUES ($1, $2, $3, 'mock', $4, $5)
                    ON CONFLICT (asset_id, hostname) DO NOTHING
                    """,
                    uuid.uuid4(), asset_id, hostname, first_seen, last_seen,
                )

                # inference result
                await conn.execute(
                    """
                    INSERT INTO inference_results (id, asset_id, device_type, behavior_type,
                                                   confidence, method, created_at)
                    VALUES ($1, $2, $3, $4, $5, 'mock-seed', $6)
                    ON CONFLICT (asset_id) DO UPDATE
                       SET device_type   = EXCLUDED.device_type,
                           behavior_type = EXCLUDED.behavior_type,
                           confidence    = EXCLUDED.confidence
                    """,
                    uuid.uuid4(), asset_id,
                    tmpl["device_type"], tmpl["behavior_type"],
                    confidence, last_seen,
                )

                # behaviors (ports)
                for port, service in tmpl["ports"]:
                    await conn.execute(
                        """
                        INSERT INTO behaviors (id, asset_id, protocol, port, service, frequency,
                                               first_seen, last_seen)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (asset_id, protocol, port, service) DO UPDATE
                           SET frequency = behaviors.frequency + EXCLUDED.frequency,
                               last_seen = GREATEST(behaviors.last_seen, EXCLUDED.last_seen)
                        """,
                        uuid.uuid4(), asset_id, "tcp", port, service,
                        rng.randint(5, 500), first_seen, last_seen,
                    )

                # attach 0-3 CVEs (biased: IoMT / Server more likely to have them)
                n_vulns = rng.choices(
                    [0, 1, 2, 3],
                    weights=[35, 35, 20, 10] if tmpl["device_type"] in ("IoMT", "Server")
                            else [60, 25, 10, 5],
                )[0]
                picked = rng.sample(cve_ids, k=min(n_vulns, len(cve_ids)))
                for vid in picked:
                    await conn.execute(
                        """
                        INSERT INTO asset_vulnerabilities (id, asset_id, vulnerability_id, detected_at)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (asset_id, vulnerability_id) DO NOTHING
                        """,
                        uuid.uuid4(), asset_id, vid, last_seen,
                    )

        # 5) Seed a handful of aggregated connections between local assets
        local_assets = await conn.fetch(
            """
            SELECT a.id, ai.ip_address
            FROM assets a JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            LIMIT 200
            """,
            subnets,
        )
        if len(local_assets) >= 2:
            existing_conns = await conn.fetchval("SELECT COUNT(*) FROM connections") or 0
            if existing_conns < 30:
                for _ in range(80):
                    src = rng.choice(local_assets)
                    dst = rng.choice(local_assets)
                    if src["id"] == dst["id"]:
                        continue
                    proto, svc, port = rng.choice([
                        ("tcp", "https", 443), ("tcp", "http", 80),
                        ("tcp", "ssh", 22),    ("tcp", "dicom", 104),
                        ("tcp", "postgres", 5432), ("tcp", "smb", 445),
                    ])
                    await conn.execute(
                        """
                        INSERT INTO connections
                            (id, src_asset_id, dst_asset_id, src_ip, dst_ip,
                             src_port, dst_port, protocol, service,
                             bytes_sent, bytes_received, timestamp)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        """,
                        uuid.uuid4(), src["id"], dst["id"],
                        src["ip_address"], dst["ip_address"],
                        rng.randint(30_000, 65_000), port,
                        proto, svc,
                        rng.randint(1_000, 1_000_000),
                        rng.randint(1_000, 5_000_000),
                        now - timedelta(minutes=rng.randint(0, 60 * 48)),
                    )

        # 6) Seed a few sample alerts so the Alerts page isn't empty
        sample_asset_id = await conn.fetchval(
            """
            SELECT a.id FROM assets a
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            JOIN asset_vulnerabilities av ON av.asset_id = a.id
            WHERE ai.ip_address <<= ANY($1::inet[])
            LIMIT 1
            """,
            subnets,
        )
        if sample_asset_id:
            existing_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts") or 0
            if existing_alerts == 0:
                alert_samples = [
                    ("vulnerability", "high",
                     "Phat hien CVE nghiem trong tren thiet bi IoMT"),
                    ("anomaly", "medium",
                     "Hanh vi mang bat thuong: ket noi ra port la"),
                    ("vulnerability", "critical",
                     "CVSS 10.0 phat hien tren host quan trong"),
                ]
                for atype, sev, msg in alert_samples:
                    await conn.execute(
                        """
                        INSERT INTO alerts (id, alert_type, severity, message,
                                            asset_id, status)
                        VALUES ($1, $2, $3, $4, $5, 'new')
                        ON CONFLICT DO NOTHING
                        """,
                        uuid.uuid4(), atype, sev, msg, sample_asset_id,
                    )

        # Summary
        asset_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM assets a
            JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
            WHERE ai.ip_address <<= ANY($1::inet[])
            """,
            subnets,
        )
        cve_count = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities")
        link_count = await conn.fetchval("SELECT COUNT(*) FROM asset_vulnerabilities")
        print(
            f"Seed complete: {asset_count} assets in scope, "
            f"{cve_count} CVEs in catalog, {link_count} asset-CVE links."
        )
    finally:
        await conn.close()


def main() -> int:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--assets", type=int, default=60,
                   help="Target number of assets in scope (default: 60)")
    args = p.parse_args()
    asyncio.run(seed(target_assets=args.assets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
