"""Main orchestrator — generates realistic Zeek TSV log files for a hospital network."""

from __future__ import annotations

import ipaddress
import random
import string
import time
from typing import Dict, List

from passive_asset_intel.generator.models import (
    DeviceTypeEnum,
    GenerateResult,
    NetworkConfig,
)
from passive_asset_intel.generator.profiles import (
    PROFILES_BY_TYPE,
    DeviceProfile,
)
from passive_asset_intel.generator.tsv_writer import TsvWriter


def _rand_uid() -> str:
    """Generate a Zeek-style connection UID: 'C' + 18 alphanumeric chars."""
    return "C" + "".join(
        random.choices(string.ascii_letters + string.digits, k=18)
    )


def _rand_mac(prefix: str) -> str:
    """Extend a 3-octet MAC prefix with 3 random octets (uppercase)."""
    suffix = [f"{random.randint(0, 255):02X}" for _ in range(3)]
    return f"{prefix}:{suffix[0]}:{suffix[1]}:{suffix[2]}"


def _nth_host(subnet: str, n: int) -> str:
    """Return the nth usable host in a subnet (n=0 → first host after gateway).

    Skips .0 (network), .1 (gateway), and broadcast address.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    # Start from .2 — .0 is network, .1 is gateway
    base_int = int(net.network_address) + 2
    ip_int = base_int + n
    # Clamp away from broadcast
    if ip_int >= int(net.broadcast_address):
        ip_int = int(net.broadcast_address) - 1
    return str(ipaddress.ip_address(ip_int))


def _gateway(subnet: str) -> str:
    """Return the .1 address of a subnet."""
    net = ipaddress.ip_network(subnet, strict=False)
    return str(ipaddress.ip_address(int(net.network_address) + 1))


class DemoDataGenerator:
    """Generates Zeek TSV logs for a simulated hospital network."""

    def __init__(self, config: NetworkConfig, output_dir: str) -> None:
        self.config = config
        self.output_dir = output_dir
        self.writer = TsvWriter(output_dir)
        self.devices: List[dict] = []
        self.total_events = 0

    # ── public API ──────────────────────────────────────────────────

    def generate(self) -> GenerateResult:
        """Run the full generation pipeline and return a result summary."""
        try:
            self._generate_devices()
            self._generate_events()
            self.writer.close()
        except Exception:
            self.writer.close()
            raise

        device_counts: Dict[str, int] = {}
        for d in self.devices:
            dt = d["device_type"]
            device_counts[dt] = device_counts.get(dt, 0) + 1

        return GenerateResult(
            status="ok",
            files_written=self.writer.files_written,
            device_counts=device_counts,
            total_devices=len(self.devices),
            total_events=self.total_events,
            log_dir=self.output_dir,
            message=(
                f"Generated {len(self.devices)} devices across "
                f"{len(self.config.vlans)} VLANs with {self.total_events} events"
            ),
        )

    # ── device generation ───────────────────────────────────────────

    def _generate_devices(self) -> None:
        for vlan in self.config.vlans:
            profiles = PROFILES_BY_TYPE.get(
                vlan.device_type.value, PROFILES_BY_TYPE["Unknown"]
            )
            if not profiles:
                profiles = PROFILES_BY_TYPE["Unknown"]

            gateway_ip = vlan.gateway_ip or _gateway(vlan.subnet)

            for i in range(vlan.device_count):
                profile: DeviceProfile = profiles[i % len(profiles)]
                ip = _nth_host(vlan.subnet, i)
                mac = _rand_mac(profile.mac_prefix)
                hostname_short = f"{profile.hostname_prefix}-{i + 1:02d}"
                hostname_fqdn = f"{hostname_short}.{self.config.domain}"

                self.devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname_short,
                    "hostname_fqdn": hostname_fqdn,
                    "profile": profile,
                    "vlan": vlan,
                    "device_type": vlan.device_type.value,
                    "gateway_ip": gateway_ip,
                    "dns_server": self.config.dns_server,
                    "domain": self.config.domain,
                })

    # ── event generation ────────────────────────────────────────────

    def _device_pool(self, device_type: str) -> List[dict]:
        return [d for d in self.devices if d["device_type"] == device_type]

    def _pick_server(self) -> dict:
        servers = self._device_pool("Server")
        if servers:
            return random.choice(servers)
        # Fallback: pick any device
        return random.choice(self.devices)

    def _pick_nvr(self) -> dict:
        servers = self._device_pool("Server")
        if servers:
            return servers[0]
        return self._pick_server()

    def _random_ts_for_device(self, base_ts: float, device_type: str) -> float:
        """Pick a random timestamp for a device based on its work profile."""
        days = self.config.simulate_days
        total_seconds = days * 86400

        if device_type == "Workstation":
            # 70% during working hours 07:00-18:00
            if random.random() < 0.7:
                day_offset = random.randint(0, max(0, days - 1))
                hour = random.randint(7, 17)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                return base_ts + day_offset * 86400 + hour * 3600 + minute * 60 + second
            else:
                return base_ts + random.uniform(0, total_seconds)

        if device_type == "IoMT":
            # Slight peak 07:00-20:00
            if random.random() < 0.65:
                day_offset = random.randint(0, max(0, days - 1))
                hour = random.randint(7, 19)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                return base_ts + day_offset * 86400 + hour * 3600 + minute * 60 + second
            else:
                return base_ts + random.uniform(0, total_seconds)

        # Server, Network, IoT, Unknown → uniform 24h
        return base_ts + random.uniform(0, total_seconds)

    def _random_conn_state(self) -> tuple[str, float, int, int]:
        """Pick a random conn_state and matching duration/bytes."""
        r = random.random()
        if r < 0.85:
            state = "SF"
            duration = random.uniform(0.1, 30.0)
            orig_bytes = random.randint(500, 500_000)
            resp_bytes = random.randint(1000, 5_000_000)
        elif r < 0.95:
            state = "RSTO"
            duration = random.uniform(0.01, 5.0)
            orig_bytes = 0
            resp_bytes = 0
        else:
            state = "S0"
            duration = 0.0
            orig_bytes = 0
            resp_bytes = 0
        return state, duration, orig_bytes, resp_bytes

    def _render_dns_query(self, template: str, domain: str) -> str:
        return template.replace("{domain}", domain)

    def _generate_events(self) -> None:
        now = time.time()
        base_ts = now - self.config.simulate_days * 86400

        for device in self.devices:
            self._generate_device_events(device, base_ts)

    def _generate_device_events(self, device: dict, base_ts: float) -> None:
        profile: DeviceProfile = device["profile"]
        device_type: str = device["device_type"]
        src_ip: str = device["ip"]
        domain: str = device["domain"]
        dns_server: str = device["dns_server"]

        # ── 1. DHCP event (always one at start) ─────────────────────
        dhcp_ts = base_ts + random.uniform(0, 300)
        gw = device["gateway_ip"]
        self.writer.write_dhcp(
            ts=dhcp_ts,
            uid=_rand_uid(),
            src_ip="0.0.0.0",
            src_port=68,
            dst_ip="255.255.255.255",
            dst_port=67,
            mac=device["mac"],
            assigned_ip=src_ip,
            lease_time=86400.0,
            hostname=device["hostname"],
            client_fqdn=device["hostname_fqdn"],
            vendor_class=profile.dhcp_vendor_class,
        )
        self.total_events += 1

        remaining = max(0, self.config.events_per_device - 1)

        # ── 2. Build weighted event plan per device type ────────────
        plan = self._event_plan(device_type, remaining)

        for kind in plan:
            ts = self._random_ts_for_device(base_ts, device_type)
            if kind == "conn":
                self._emit_conn(device, ts)
            elif kind == "conn_pacs":
                self._emit_conn(device, ts, force_port=104, force_service="dicom")
            elif kind == "conn_his":
                self._emit_conn(device, ts, force_port=2575, force_service="hl7")
            elif kind == "conn_rdp":
                self._emit_conn(device, ts, force_port=3389, force_service="rdp")
            elif kind == "conn_rtsp":
                self._emit_conn(device, ts, force_port=554, force_service="rtsp",
                                force_dst=self._pick_nvr())
            elif kind == "conn_snmp":
                self._emit_conn(device, ts, force_port=161, force_service="snmp")
            elif kind == "conn_ssh":
                self._emit_conn(device, ts, force_port=22, force_service="ssh")
            elif kind == "conn_https":
                self._emit_conn(device, ts, force_port=443, force_service="ssl")
            elif kind == "dns":
                self._emit_dns(device, ts)
            elif kind == "http":
                self._emit_http(device, ts)
            elif kind == "ssl":
                self._emit_ssl(device, ts)

            self.total_events += 1

    def _event_plan(self, device_type: str, n: int) -> List[str]:
        """Return a shuffled list of n event-kind tokens according to type mix."""
        if device_type == "IoMT":
            weights = {
                "conn_pacs": 0.40,
                "conn_his": 0.20,
                "dns": 0.20,
                "http": 0.10,
                "ssl": 0.10,
            }
        elif device_type == "Workstation":
            weights = {
                "conn_https": 0.30,
                "dns": 0.20,
                "http": 0.20,
                "ssl": 0.20,
                "conn_rdp": 0.10,
            }
        elif device_type == "IoT":
            weights = {
                "conn_rtsp": 0.50,
                "dns": 0.20,
                "conn_https": 0.20,
                "ssl": 0.10,
            }
        elif device_type == "Server":
            weights = {
                "conn": 0.40,
                "dns": 0.30,
                "ssl": 0.20,
                "http": 0.10,
            }
        elif device_type == "Network":
            weights = {
                "conn_snmp": 0.50,
                "conn_ssh": 0.30,
                "ssl": 0.20,
            }
        else:
            weights = {"conn": 0.5, "dns": 0.3, "ssl": 0.2}

        plan: List[str] = []
        for kind, frac in weights.items():
            count = int(round(n * frac))
            plan.extend([kind] * count)

        # Pad any rounding shortfall with the most-weighted kind
        while len(plan) < n:
            top = max(weights, key=weights.get)
            plan.append(top)
        plan = plan[:n]

        random.shuffle(plan)
        return plan

    # ── individual event emitters ───────────────────────────────────

    def _emit_conn(
        self,
        device: dict,
        ts: float,
        force_port: int | None = None,
        force_service: str | None = None,
        force_dst: dict | None = None,
    ) -> None:
        profile: DeviceProfile = device["profile"]
        src_ip = device["ip"]

        if force_dst is not None:
            dst_device = force_dst
        else:
            dst_device = self._pick_server()
        dst_ip = dst_device["ip"]

        if force_port is not None:
            dst_port = force_port
            service = force_service or dst_device["profile"].services.get(force_port, "-")
        else:
            # Pick a port from the destination's open ports
            dst_profile: DeviceProfile = dst_device["profile"]
            if dst_profile.open_ports:
                dst_port = random.choice(dst_profile.open_ports)
                service = dst_profile.services.get(dst_port, "-")
            else:
                dst_port = 443
                service = "ssl"

        src_port = random.randint(40000, 60000)
        proto = "tcp"
        state, duration, orig_b, resp_b = self._random_conn_state()

        self.writer.write_conn(
            ts=ts,
            uid=_rand_uid(),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            service=service,
            duration=duration,
            orig_bytes=orig_b,
            resp_bytes=resp_b,
            conn_state=state,
        )

    def _emit_dns(self, device: dict, ts: float) -> None:
        profile: DeviceProfile = device["profile"]
        domain: str = device["domain"]
        src_ip: str = device["ip"]
        dns_server: str = device["dns_server"]

        if profile.dns_queries:
            query = self._render_dns_query(random.choice(profile.dns_queries), domain)
        else:
            query = f"host.{domain}"

        # Resolve answer to a random device IP if query looks internal,
        # else use a plausible external IP
        if query.endswith(domain):
            # Prefer a server IP
            servers = self._device_pool("Server")
            answer_ip = servers[0]["ip"] if servers else "10.0.0.10"
        else:
            answer_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}." \
                        f"{random.randint(0, 255)}.{random.randint(1, 254)}"

        self.writer.write_dns(
            ts=ts,
            uid=_rand_uid(),
            src_ip=src_ip,
            query=query,
            answer_ip=answer_ip,
            dns_server=dns_server,
            src_port=random.randint(40000, 65000),
        )

    def _emit_http(self, device: dict, ts: float) -> None:
        profile: DeviceProfile = device["profile"]
        src_ip: str = device["ip"]
        domain: str = device["domain"]

        dst_device = self._pick_server()
        dst_ip = dst_device["ip"]

        user_agent = random.choice(profile.user_agents) if profile.user_agents else "-"
        method = random.choice(["GET", "GET", "GET", "POST"])
        host = f"his.{domain}"
        uri = random.choice(["/", "/api/v1/patients", "/login", "/api/health", "/static/app.js"])
        status_code = random.choices([200, 200, 200, 304, 404, 500], k=1)[0]

        self.writer.write_http(
            ts=ts,
            uid=_rand_uid(),
            src_ip=src_ip,
            src_port=random.randint(40000, 60000),
            dst_ip=dst_ip,
            dst_port=80,
            method=method,
            host=host,
            uri=uri,
            user_agent=user_agent,
            status_code=status_code,
            response_body_len=random.randint(500, 50000),
        )

    def _emit_ssl(self, device: dict, ts: float) -> None:
        profile: DeviceProfile = device["profile"]
        src_ip: str = device["ip"]
        domain: str = device["domain"]

        dst_device = self._pick_server()
        dst_ip = dst_device["ip"]

        # Choose a realistic SNI from the profile's DNS queries, else his.{domain}
        if profile.dns_queries:
            sni = self._render_dns_query(random.choice(profile.dns_queries), domain)
        else:
            sni = f"his.{domain}"

        self.writer.write_ssl(
            ts=ts,
            uid=_rand_uid(),
            src_ip=src_ip,
            src_port=random.randint(40000, 60000),
            dst_ip=dst_ip,
            dst_port=443,
            server_name=sni,
        )
