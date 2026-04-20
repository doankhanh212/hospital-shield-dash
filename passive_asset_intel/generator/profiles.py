"""Device profiles for each device type — vendor, MAC prefix, ports, services, etc."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DeviceProfile:
    vendor: str
    mac_prefix: str  # e.g. "00:1A:2B"
    dhcp_vendor_class: str
    user_agents: List[str]
    open_ports: List[int]
    services: Dict[int, str]
    dns_queries: List[str]  # {domain} placeholder replaced at runtime
    hostname_prefix: str
    os_name: str


# ── IoMT (Internet of Medical Things) ────────────────────────────────

IOMT_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="GE Healthcare",
        mac_prefix="00:1A:2B",
        dhcp_vendor_class="GE-HealthCare-MRI",
        user_agents=["GE-MRI/3.2", "GE-CT/4.1"],
        open_ports=[104, 2575, 80, 443],
        services={104: "dicom", 2575: "hl7", 443: "ssl", 80: "http"},
        dns_queries=["pacs.{domain}", "his.{domain}", "update.gehealthcare.com"],
        hostname_prefix="ge-mri",
        os_name="Embedded Linux",
    ),
    DeviceProfile(
        vendor="Philips Healthcare",
        mac_prefix="00:2B:3C",
        dhcp_vendor_class="Philips-CT-Scanner",
        user_agents=["Philips-CT/2.1", "Philips-MRI/3.0"],
        open_ports=[104, 80, 443, 11112],
        services={104: "dicom", 11112: "dicom-tls", 443: "ssl"},
        dns_queries=["pacs.{domain}", "philips-update.philips.com"],
        hostname_prefix="philips-ct",
        os_name="Windows 10 IoT",
    ),
    DeviceProfile(
        vendor="Siemens Healthineers",
        mac_prefix="00:3C:4D",
        dhcp_vendor_class="Siemens-Ultrasound",
        user_agents=["Siemens-US/5.0"],
        open_ports=[104, 443, 80],
        services={104: "dicom", 443: "ssl"},
        dns_queries=["pacs.{domain}", "siemens-health.com"],
        hostname_prefix="siemens-us",
        os_name="VxWorks",
    ),
    DeviceProfile(
        vendor="Mindray",
        mac_prefix="00:4D:5E",
        dhcp_vendor_class="Mindray-PatientMonitor",
        user_agents=["Mindray-Monitor/2.0"],
        open_ports=[80, 443, 2575],
        services={2575: "hl7", 443: "ssl"},
        dns_queries=["his.{domain}", "adt.{domain}"],
        hostname_prefix="mindray-mon",
        os_name="Embedded Linux",
    ),
    DeviceProfile(
        vendor="Baxter International",
        mac_prefix="00:5E:6F",
        dhcp_vendor_class="Baxter-InfusionPump",
        user_agents=["Baxter-Pump/1.5"],
        open_ports=[80, 443],
        services={443: "ssl"},
        dns_queries=["pharmacy.{domain}", "his.{domain}"],
        hostname_prefix="baxter-pump",
        os_name="QNX",
    ),
]

# ── Workstations ─────────────────────────────────────────────────────

WORKSTATION_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="Dell",
        mac_prefix="00:6F:7A",
        dhcp_vendor_class="MSFT 5.0",
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0",
        ],
        open_ports=[135, 445, 3389, 80, 443],
        services={3389: "rdp", 445: "smb", 443: "ssl", 80: "http"},
        dns_queries=[
            "his.{domain}",
            "pacs.{domain}",
            "outlook.office365.com",
            "login.microsoftonline.com",
            "teams.microsoft.com",
        ],
        hostname_prefix="ws-dell",
        os_name="Windows 10",
    ),
    DeviceProfile(
        vendor="HP",
        mac_prefix="00:7A:8B",
        dhcp_vendor_class="MSFT 5.0",
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "Chrome/121.0.0.0",
        ],
        open_ports=[135, 445, 3389, 443],
        services={3389: "rdp", 443: "ssl"},
        dns_queries=[
            "his.{domain}",
            "teams.microsoft.com",
            "windowsupdate.com",
        ],
        hostname_prefix="ws-hp",
        os_name="Windows 11",
    ),
    DeviceProfile(
        vendor="Apple",
        mac_prefix="00:8B:9C",
        dhcp_vendor_class="MSFT 5.0",
        user_agents=[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
            "AppleWebKit/605.1.15 Safari/605.1.15",
        ],
        open_ports=[443, 22, 5900],
        services={443: "ssl", 5900: "vnc", 22: "ssh"},
        dns_queries=["his.{domain}", "icloud.com", "apple.com"],
        hostname_prefix="ws-mac",
        os_name="macOS",
    ),
]

# ── IoT (cameras, environmental sensors) ─────────────────────────────

IOT_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="Hikvision",
        mac_prefix="00:9C:AD",
        dhcp_vendor_class="Hikvision-IPC",
        user_agents=["Hikvision-HTTP/1.0"],
        open_ports=[80, 443, 554, 8000],
        services={554: "rtsp", 443: "ssl", 80: "http"},
        dns_queries=["nvr.{domain}", "time.nist.gov"],
        hostname_prefix="cam-hik",
        os_name="Embedded Linux",
    ),
    DeviceProfile(
        vendor="Axis Communications",
        mac_prefix="00:AD:BE",
        dhcp_vendor_class="AXIS",
        user_agents=["AXIS-HTTP/3.0"],
        open_ports=[80, 443, 554],
        services={554: "rtsp", 443: "ssl"},
        dns_queries=["nvr.{domain}", "axis.com"],
        hostname_prefix="cam-axis",
        os_name="Embedded Linux",
    ),
    DeviceProfile(
        vendor="Dahua Technology",
        mac_prefix="00:BE:CF",
        dhcp_vendor_class="Dahua-IPC",
        user_agents=["Dahua-HTTP/2.0"],
        open_ports=[80, 443, 554, 37777],
        services={554: "rtsp", 443: "ssl"},
        dns_queries=["nvr.{domain}"],
        hostname_prefix="cam-dahua",
        os_name="Embedded Linux",
    ),
]

# ── Servers ──────────────────────────────────────────────────────────

SERVER_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="Dell Technologies",
        mac_prefix="00:CF:D0",
        dhcp_vendor_class="linux",
        user_agents=[],
        open_ports=[22, 80, 443, 104, 5432, 8080],
        services={22: "ssh", 104: "dicom", 443: "ssl", 5432: "postgres"},
        dns_queries=[
            "update.ubuntu.com",
            "security.ubuntu.com",
            "ntp.ubuntu.com",
        ],
        hostname_prefix="pacs-srv",
        os_name="Ubuntu 22.04",
    ),
    DeviceProfile(
        vendor="HP Enterprise",
        mac_prefix="00:D0:E1",
        dhcp_vendor_class="linux",
        user_agents=[],
        open_ports=[22, 443, 3000, 8080],
        services={22: "ssh", 443: "ssl"},
        dns_queries=["update.ubuntu.com", "his.{domain}"],
        hostname_prefix="his-srv",
        os_name="Ubuntu 22.04",
    ),
    DeviceProfile(
        vendor="Dell Technologies",
        mac_prefix="00:CF:D1",
        dhcp_vendor_class="linux",
        user_agents=[],
        open_ports=[22, 443, 9200, 5601],
        services={22: "ssh", 443: "ssl", 9200: "elasticsearch"},
        dns_queries=["update.ubuntu.com"],
        hostname_prefix="log-srv",
        os_name="Ubuntu 22.04",
    ),
]

# ── Network devices ──────────────────────────────────────────────────

NETWORK_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="Cisco Systems",
        mac_prefix="00:E1:F2",
        dhcp_vendor_class="cisco",
        user_agents=[],
        open_ports=[22, 23, 161, 443, 179],
        services={161: "snmp", 443: "ssl", 22: "ssh", 179: "bgp"},
        dns_queries=[],
        hostname_prefix="sw-cisco",
        os_name="IOS-XE",
    ),
    DeviceProfile(
        vendor="Ubiquiti Networks",
        mac_prefix="00:F2:03",
        dhcp_vendor_class="ubiquiti",
        user_agents=["AirOS/8.0"],
        open_ports=[22, 80, 443, 8080],
        services={443: "ssl", 22: "ssh"},
        dns_queries=["inform.ui.com", "time.cloudflare.com"],
        hostname_prefix="ap-ubnt",
        os_name="UniFi OS",
    ),
    DeviceProfile(
        vendor="Palo Alto Networks",
        mac_prefix="00:03:14",
        dhcp_vendor_class="panos",
        user_agents=[],
        open_ports=[22, 443, 3978],
        services={443: "ssl", 22: "ssh"},
        dns_queries=["updates.paloaltonetworks.com"],
        hostname_prefix="fw-pa",
        os_name="PAN-OS",
    ),
]

# ── Unknown ──────────────────────────────────────────────────────────

UNKNOWN_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        vendor="Unknown",
        mac_prefix="00:11:22",
        dhcp_vendor_class="-",
        user_agents=[],
        open_ports=[80, 443],
        services={443: "ssl"},
        dns_queries=[],
        hostname_prefix="unknown",
        os_name="Unknown",
    ),
]

# ── Lookup map ───────────────────────────────────────────────────────

PROFILES_BY_TYPE: Dict[str, List[DeviceProfile]] = {
    "IoMT": IOMT_PROFILES,
    "IoT": IOT_PROFILES,
    "Workstation": WORKSTATION_PROFILES,
    "Server": SERVER_PROFILES,
    "Network": NETWORK_PROFILES,
    "Unknown": UNKNOWN_PROFILES,
}
