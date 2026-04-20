"""Classification rules for the inference engine.

All rules are pure data structures — no logic here.  The device_classifier
module reads these and applies them against asset data.

Each rule dict has the following shape::

    {
        "match_field": str,      # what to match against
        "match_value": str,      # value or pattern to match
        "match_type": str,       # "exact", "contains" (case-insensitive), or "regex"
        "infer": {               # what the match implies
            "device_type": str | None,
            "os": str | None,
            "os_version": str | None,
            "vendor": str | None,
        },
        "weight": float,         # 0.0–1.0, how confident this signal is
        "evidence_type": str,    # for the inference_evidence table
    }
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# PROTOCOL / PORT RULES  (behaviors table — match on dst_port)
# ---------------------------------------------------------------------------

PORT_RULES: list[dict] = [
    {
        "match_field": "port",
        "match_value": 104,
        "match_type": "exact",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "port",
        "label": "DICOM",
    },
    {
        "match_field": "port",
        "match_value": 2575,
        "match_type": "exact",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "port",
        "label": "HL7",
    },
    {
        "match_field": "port",
        "match_value": 11112,
        "match_type": "exact",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "port",
        "label": "DICOM-TLS",
    },
    {
        "match_field": "port",
        "match_value": 554,
        "match_type": "exact",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "port",
        "label": "RTSP",
    },
    # ----- Printers -----
    {
        "match_field": "port",
        "match_value": 9100,
        "match_type": "exact",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},
        "weight": 0.90,
        "evidence_type": "port",
        "label": "Raw Print (JetDirect)",
    },
    {
        "match_field": "port",
        "match_value": 631,
        "match_type": "exact",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "port",
        "label": "IPP",
    },
    {
        "match_field": "port",
        "match_value": 515,
        "match_type": "exact",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "port",
        "label": "LPD",
    },
    # ----- IP Cameras (additional) -----
    {
        "match_field": "port",
        "match_value": 8554,
        "match_type": "exact",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "port",
        "label": "RTSP-alt",
    },
    {
        "match_field": "port",
        "match_value": 37777,
        "match_type": "exact",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.70,
        "evidence_type": "port",
        "label": "Dahua-RTSP",
    },
    {
        "match_field": "port",
        "match_value": 34567,
        "match_type": "exact",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None},
        "weight": 0.65,
        "evidence_type": "port",
        "label": "DVR-API",
    },
    {
        "match_field": "port",
        "match_value": 1883,
        "match_type": "exact",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "port",
        "label": "MQTT",
    },
    {
        "match_field": "port",
        "match_value": 502,
        "match_type": "exact",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "port",
        "label": "Modbus",
    },
    {
        "match_field": "port",
        "match_value": 161,
        "match_type": "exact",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.6,
        "evidence_type": "port",
        "label": "SNMP",
    },
    {
        "match_field": "port",
        "match_value": 179,
        "match_type": "exact",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "port",
        "label": "BGP",
    },
    {
        "match_field": "port",
        "match_value": 3389,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.5,
        "evidence_type": "port",
        "label": "RDP",
    },
    {
        "match_field": "port",
        "match_value": 5900,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.5,
        "evidence_type": "port",
        "label": "VNC",
    },
    {
        "match_field": "port",
        "match_value": 10051,
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.7,
        "evidence_type": "port",
        "label": "Zabbix Agent",
    },
    {
        "match_field": "port",
        "match_value": 2087,
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "port",
        "label": "cPanel SSL",
    },
    {
        "match_field": "port",
        "match_value": 137,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "port",
        "label": "NetBIOS Name Service",
    },
    {
        "match_field": "port",
        "match_value": 138,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "port",
        "label": "NetBIOS Datagram",
    },
    {
        "match_field": "port",
        "match_value": 5355,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "port",
        "label": "LLMNR",
    },
    {
        "match_field": "port",
        "match_value": 67,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.5,
        "evidence_type": "port",
        "label": "DHCP Server",
    },
    {
        "match_field": "port",
        "match_value": 68,
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.5,
        "evidence_type": "port",
        "label": "DHCP Client",
    },
    {
        "match_field": "port",
        "match_value": 5060,
        "match_type": "exact",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "port",
        "label": "SIP",
    },
    {
        "match_field": "port",
        "match_value": 6831,
        "match_type": "exact",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.7,
        "evidence_type": "port",
        "label": "sFlow",
    },
]

# ---------------------------------------------------------------------------
# DHCP VENDOR CLASS RULES  (fingerprints.dhcp_vendor — substring, case-insensitive)
# ---------------------------------------------------------------------------

DHCP_RULES: list[dict] = [
    {
        "match_field": "dhcp_vendor",
        "match_value": "MSFT",
        "match_type": "contains",
        "infer": {"device_type": None, "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "android",
        "match_type": "contains",
        "infer": {"device_type": None, "os": "Android", "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "ubuntu",
        "match_type": "contains",
        "infer": {"device_type": None, "os": "Ubuntu Linux", "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "linux",
        "match_type": "contains",
        "infer": {"device_type": None, "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "raspbian",
        "match_type": "contains",
        "infer": {"device_type": None, "os": "Raspberry Pi OS", "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "vxworks",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": "VxWorks", "os_version": None, "vendor": None},
        "weight": 0.95,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "qnx",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": "QNX", "os_version": None, "vendor": None},
        "weight": 0.95,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "cisco",
        "match_type": "contains",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Cisco"},
        "weight": 0.9,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "polycom",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "zebra",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "dhcp_vendor",
    },
    # ----- Printers (DHCP vendor class / option 60) -----
    {
        "match_field": "dhcp_vendor",
        "match_value": "HP JETDIRECT",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.95,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "JETDIRECT",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "RICOH",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "BROTHER",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "CANON",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Canon"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "EPSON",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "KYOCERA",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Kyocera"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "XEROX",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Xerox"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    # ----- IP Cameras (DHCP vendor class) -----
    {
        "match_field": "dhcp_vendor",
        "match_value": "hikvision",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hikvision"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "dahua",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
    {
        "match_field": "dhcp_vendor",
        "match_value": "axis communications",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.90,
        "evidence_type": "dhcp_vendor",
    },
]

# ---------------------------------------------------------------------------
# USER AGENT RULES  (fingerprints.user_agent — regex match)
# ---------------------------------------------------------------------------

USER_AGENT_RULES: list[dict] = [
    {
        "match_field": "user_agent",
        "match_value": r"Windows NT 10",
        "match_type": "regex",
        "infer": {"device_type": None, "os": "Windows 10", "os_version": "10", "vendor": None},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Windows NT 6\.1",
        "match_type": "regex",
        "infer": {"device_type": None, "os": "Windows 7", "os_version": "6.1", "vendor": None},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Linux.*Android",
        "match_type": "regex",
        "infer": {"device_type": None, "os": "Android", "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"GE.?MRI",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "GE Healthcare"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"GE.?CT",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "GE Healthcare"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Philips",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Philips"},
        "weight": 0.9,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Siemens",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Siemens"},
        "weight": 0.9,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Cisco",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Cisco"},
        "weight": 0.85,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"curl|python|Go-http|zgrab",
        "match_type": "regex",
        "infer": {"device_type": "Scanner", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "user_agent",
    },
    # Generic Mozilla UAs are kept at a low weight on purpose: every
    # workstation browser looks like this. They should nudge, not drive.
    {
        "match_field": "user_agent",
        "match_value": r"Mozilla.*Windows",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Mozilla.*Mac",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "macOS", "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Mozilla.*(?:X11; Linux|Linux x86_64)",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Mozilla.*CrOS",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "ChromeOS", "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Microsoft-CryptoAPI",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Prometheus/",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"WordPress/",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "user_agent",
    },
    # ----- Printers -----
    {
        "match_field": "user_agent",
        "match_value": r"HP.?LaserJet|HP.?OfficeJet|HP.?DeskJet|HP.?PageWide",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"RICOH.?MP|RICOH.?SP|Aficio",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Canon.?(iR|LBP|MF\d|PIXMA|imageRUNNER)",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Canon"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"EPSON.?(WorkForce|EcoTank|SureColor|L\d{3,}|ET-)",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Konica.?Minolta|Kyocera.?ECOSYS|Xerox.?(Phaser|WorkCentre|VersaLink)|Lexmark",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},
        "weight": 0.90,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Brother.?(MFC|DCP|HL-|ADS-)",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    # ----- IP Cameras -----
    {
        "match_field": "user_agent",
        "match_value": r"Hikvision|HikVision|DS-2[A-Z]{2}|iVMS",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hikvision"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Dahua|DH-IPC|LeChange",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"AXIS/|Axis.?VAPIX|AxisCamera",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Hanwha|Samsung.?Techwin|SNC-[A-Z]",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hanwha"},
        "weight": 0.90,
        "evidence_type": "user_agent",
    },
    # ----- IoT devices -----
    {
        "match_field": "user_agent",
        "match_value": r"ESP(?:8266|32)|Arduino|MicroPython|micropython|esp-idf",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.90,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"paho.?mqtt|eclipse-mqtt|MQTT",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Zabbix|PRTG|NetFlow",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.70,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Baxter[-/]Pump",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Baxter"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"Mindray[-/]Monitor",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Mindray"},
        "weight": 0.95,
        "evidence_type": "user_agent",
    },
    {
        "match_field": "user_agent",
        "match_value": r"AhrefsBot|MJ12bot|MegaIndex|CensysInspect|coccocbot|DotBot|Googlebot|meta-externalagent|facebookexternalhit|Palo Alto Networks.*Scanning-activity|visionheight\.com/scan|crawler",
        "match_type": "regex",
        "infer": {"device_type": "Scanner", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "user_agent",
    },
]

# ---------------------------------------------------------------------------
# JA3 CATEGORY RULES  (categorized client TLS fingerprints — BEHAVIOR only)
# ---------------------------------------------------------------------------
# These rules match on ja3_category (from categorizer), NOT raw hashes.
# Weight is intentionally LOW: JA3 is a behavioral hint, subordinate to
# MAC vendor, DHCP, and strong port signals.
#
# Weight range: 0.35 – 0.65  (contrast: VENDOR 0.70+, DHCP 0.75+, PORT 0.60+)

JA3_CATEGORY_RULES: list[dict] = [
    # ── Browser categories → Workstation ──────────────────────────
    {
        "match_field": "ja3_category",
        "match_value": "chrome_tls",
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "ja3_category",
    },
    {
        "match_field": "ja3_category",
        "match_value": "firefox_tls",
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "ja3_category",
    },
    {
        "match_field": "ja3_category",
        "match_value": "edge_tls",
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "ja3_category",
    },

    # ── Windows native TLS → Workstation (or Server — ambiguous) ─
    {
        "match_field": "ja3_category",
        "match_value": "windows_native_tls",
        "match_type": "exact",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.40,
        "evidence_type": "ja3_category",
    },

    # ── Scripting / automation → hints at Server or automation node
    {
        "match_field": "ja3_category",
        "match_value": "curl_cli",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.40,
        "evidence_type": "ja3_category",
    },
    {
        "match_field": "ja3_category",
        "match_value": "python_requests",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.40,
        "evidence_type": "ja3_category",
    },
    {
        "match_field": "ja3_category",
        "match_value": "go_tls",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.40,
        "evidence_type": "ja3_category",
    },
    {
        "match_field": "ja3_category",
        "match_value": "node_tls",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.40,
        "evidence_type": "ja3_category",
    },

    # ── Java TLS → could be server, Android, or middleware ────────
    {
        "match_field": "ja3_category",
        "match_value": "java_tls",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.35,
        "evidence_type": "ja3_category",
    },

    # ── OpenSSL default — massively shared, very weak signal ──────
    {
        "match_field": "ja3_category",
        "match_value": "openssl_default",
        "match_type": "exact",
        "infer": {"device_type": None, "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.20,
        "evidence_type": "ja3_category",
    },

    # ── IoT embedded TLS → IoT ────────────────────────────────────
    {
        "match_field": "ja3_category",
        "match_value": "iot_embedded_tls",
        "match_type": "exact",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "ja3_category",
    },

    # ── Medical device TLS → IoMT ─────────────────────────────────
    {
        "match_field": "ja3_category",
        "match_value": "medical_device_tls",
        "match_type": "exact",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.60,
        "evidence_type": "ja3_category",
    },
]

# ---------------------------------------------------------------------------
# JA3S CATEGORY RULES  (categorized server TLS fingerprints)
# ---------------------------------------------------------------------------
# JA3S presence means the asset acted as a TLS server.  These rules
# provide server-type hints via the server stack category.

JA3S_CATEGORY_RULES: list[dict] = [
    # ── Standard web servers → Server ─────────────────────────────
    {
        "match_field": "ja3s_category",
        "match_value": "nginx",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": "nginx"},
        "weight": 0.60,
        "evidence_type": "ja3s_category",
    },
    {
        "match_field": "ja3s_category",
        "match_value": "apache",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": "Apache"},
        "weight": 0.60,
        "evidence_type": "ja3s_category",
    },
    {
        "match_field": "ja3s_category",
        "match_value": "iis",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": "Windows Server", "os_version": None, "vendor": "Microsoft"},
        "weight": 0.65,
        "evidence_type": "ja3s_category",
    },
    {
        "match_field": "ja3s_category",
        "match_value": "litespeed",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "ja3s_category",
    },
    {
        "match_field": "ja3s_category",
        "match_value": "cloudflare",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": "Cloudflare"},
        "weight": 0.55,
        "evidence_type": "ja3s_category",
    },
    {
        "match_field": "ja3s_category",
        "match_value": "generic_server",
        "match_type": "exact",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.45,
        "evidence_type": "ja3s_category",
    },

    # ── Embedded TLS on server side → IoT / camera / printer ──────
    {
        "match_field": "ja3s_category",
        "match_value": "embedded_tls",
        "match_type": "exact",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.50,
        "evidence_type": "ja3s_category",
    },
]

# ---------------------------------------------------------------------------
# VENDOR / MAC OUI RULES  (vendor string from MAC lookup — substring, case-insensitive)
# ---------------------------------------------------------------------------

VENDOR_RULES: list[dict] = [
    {
        "match_field": "vendor",
        "match_value": "GE Healthcare",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "GE Healthcare"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Philips",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Philips"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Siemens",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Siemens"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Mindray",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Draeger",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Baxter",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Nihon Kohden",
        "match_type": "contains",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.9,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Cisco",
        "match_type": "contains",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Hikvision",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hikvision"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Dahua",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Axis",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Dell",
        "match_type": "contains",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "HP",
        "match_type": "contains",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.55,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Lenovo",
        "match_type": "contains",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "VMware",
        "match_type": "contains",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "vendor_oui",
    },
    # ----- Printers -----
    {
        "match_field": "vendor",
        "match_value": "Brother",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Epson",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Xerox",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Xerox"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Ricoh",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Lexmark",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Lexmark"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Kyocera",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Kyocera"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Konica",
        "match_type": "contains",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Konica Minolta"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    # ----- IP Cameras (additional) -----
    {
        "match_field": "vendor",
        "match_value": "Hanwha",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hanwha"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Reolink",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Reolink"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Amcrest",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Amcrest"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Uniview",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Uniview"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Bosch Security",
        "match_type": "contains",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Bosch"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    # ----- IoT -----
    {
        "match_field": "vendor",
        "match_value": "Espressif",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Espressif"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Arduino",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Arduino"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Raspberry Pi",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Raspberry Pi"},
        "weight": 0.75,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Nest Labs",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Nest"},
        "weight": 0.90,
        "evidence_type": "vendor_oui",
    },
    {
        "match_field": "vendor",
        "match_value": "Tuya",
        "match_type": "contains",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Tuya"},
        "weight": 0.85,
        "evidence_type": "vendor_oui",
    },
]

# ---------------------------------------------------------------------------
# HOSTNAME RULES  (asset hostname or DHCP-advertised hostname — regex)
# ---------------------------------------------------------------------------

HOSTNAME_RULES: list[dict] = [
    # ----- Printers -----
    {
        "match_field": "hostname",
        "match_value": r"^HP[0-9A-Fa-f]{6,}",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.85,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"^NPI[0-9A-Fa-f]{6,}",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.90,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"^BRN[0-9A-Fa-f]{6,}",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.90,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"^EPSON[0-9A-Fa-f]{6,}",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.90,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"^RICOH[0-9A-Fa-f]{4,}",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.90,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)printer|printserver|printserv",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},
        "weight": 0.65,
        "evidence_type": "hostname",
    },
    # ----- IP Cameras -----
    {
        "match_field": "hostname",
        "match_value": r"^AXIS[-_][0-9A-Fa-f]{6,}",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.92,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)ipcam|ip-cam|camera|webcam|(?:^|[._-])(nvr|dvr)(?:[._-]|$)|cctv",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None},
        "weight": 0.65,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"^WIN-[A-Z0-9]+$",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)^(desktop|laptop)[0-9A-Za-z-]*$",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},
        "weight": 0.7,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)(^|[._-])(his|pacs|ris|lis|emr|ehr)([._-]|$)",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "hostname",
    },
    # ----- Web hosting / management servers (observed in captures) -----
    {
        "match_field": "hostname",
        "match_value": r"(?i)^whmcs\d+",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": "WHMCS"},
        "weight": 0.85,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)haproxy|nginx|apache|cpanel|whm|plesk",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "hostname",
    },
    {
        "match_field": "hostname",
        "match_value": r"(?i)(^|[._-])(db|mysql|mariadb|postgres|redis|mongo|elastic)([._-]|$)",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "hostname",
    },
]

# ---------------------------------------------------------------------------
# DNS QUERY RULES  (domains queried by the asset)
# ---------------------------------------------------------------------------

DNS_RULES: list[dict] = [
    # ----- IP Cameras -----
    {
        "match_field": "dns_query",
        "match_value": r"hikvision|hikvisioneurope",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hikvision"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"\.axis\.com",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.75,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"dahuasecurity|lechange\.com",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"hanwhasecurity|samsungsecurity",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hanwha"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    # ----- Printers -----
    {
        "match_field": "dns_query",
        "match_value": r"hpprint\.com|print\.hp\.com|eprint\.hp\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"epsonconnect|print\.epson",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"\.brother\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.75,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"\.ricoh\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.75,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"ij\.start\.canon|\.canon\.com|canonprintapp",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Canon"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"\.xerox\.com|xeroxcloudprint",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Xerox"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"konicaminolta\.com|bizhub",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Konica Minolta"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    # ----- IoMT cloud portals -----
    {
        "match_field": "dns_query",
        "match_value": r"\.mindray\.com|mindraymedical",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Mindray"},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"siemens-healthineers\.com|healthcare\.siemens\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Siemens"},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"philips\.com/healthcare|usa\.philips\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Philips"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"healthcare\.ge\.com|gehealthcloud",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "GE Healthcare"},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    # ----- IP Cameras (additional) -----
    {
        "match_field": "dns_query",
        "match_value": r"uniview\.com|ezcloud\.uniview",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Uniview"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    # ----- Workstations -----
    {
        "match_field": "dns_query",
        "match_value": r"windowsupdate\.com|delivery\.mp\.microsoft\.com|events\.data\.microsoft\.com|mobile\.events\.data\.microsoft\.com|settings-win\.data\.microsoft\.com|office\.com|outlook\.office365\.com|teams\.microsoft\.com|applicationinsights\.azure\.com|githubcopilot\.com|win\d+\.ipv6\.microsoft\.com|teredo\.ipv6\.microsoft\.com",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"^WIN-[A-Z0-9]+$|^wpad$|^isatap$",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.7,
        "evidence_type": "dns",
    },
    # ----- Servers -----
    {
        "match_field": "dns_query",
        "match_value": r"grafana\.com|gitlab\.|snapcraft\.io|imunify(?:360)?\.com|cloudlinux|cpanel\.|smtp\.gmail\.com",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"updates?\.paloaltonetworks\.com",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Palo Alto Networks"},
        "weight": 0.9,
        "evidence_type": "dns",
    },
    # ----- IoT -----
    {
        "match_field": "dns_query",
        "match_value": r"mqtt\.eclipse\.org|broker\.hivemq|mosquitto",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.70,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"device\.philips|meethue\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Philips Hue"},
        "weight": 0.80,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"nest\.com|home\.nest|firebase\.google\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Nest"},
        "weight": 0.65,
        "evidence_type": "dns",
    },
    {
        "match_field": "dns_query",
        "match_value": r"iot\.amazonaws\.com|iot\.us-east|greengrass",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.65,
        "evidence_type": "dns",
    },
]

# ---------------------------------------------------------------------------
# SSL SNI RULES  (TLS server_name from client hello)
# ---------------------------------------------------------------------------

SNI_RULES: list[dict] = [
    # ----- IP Cameras -----
    {
        "match_field": "ssl_sni",
        "match_value": r"hikvision|hikvisioneurope",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Hikvision"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"\.axis\.com",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Axis"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"dahua|lechange\.com",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    # ----- Printers -----
    {
        "match_field": "ssl_sni",
        "match_value": r"hpprint\.com|eprint\.hp\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "HP"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"epsonconnect|print\.epson",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Epson"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"\.brother\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Brother"},
        "weight": 0.80,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"ij\.start\.canon|\.canon\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Canon"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"\.xerox\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Xerox"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"\.ricoh\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Ricoh"},
        "weight": 0.80,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"konicaminolta\.com",
        "match_type": "regex",
        "infer": {"device_type": "Printer", "os": None, "os_version": None, "vendor": "Konica Minolta"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    # ----- IoMT cloud portals -----
    {
        "match_field": "ssl_sni",
        "match_value": r"\.mindray\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Mindray"},
        "weight": 0.88,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"siemens-healthineers\.com|healthcare\.siemens\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Siemens"},
        "weight": 0.88,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"philips\.com/healthcare|usa\.philips\.com",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "Philips"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"healthcare\.ge\.com|gehealthcloud",
        "match_type": "regex",
        "infer": {"device_type": "IoMT", "os": None, "os_version": None, "vendor": "GE Healthcare"},
        "weight": 0.88,
        "evidence_type": "ssl_sni",
    },
    # ----- IP Cameras (additional) -----
    {
        "match_field": "ssl_sni",
        "match_value": r"uniview\.com|ezcloud\.uniview",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Uniview"},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    # ----- Workstations -----
    {
        "match_field": "ssl_sni",
        "match_value": r"events\.data\.microsoft\.com|mobile\.events\.data\.microsoft\.com|settings-win\.data\.microsoft\.com|windowsupdate\.com|applicationinsights\.azure\.com|githubcopilot\.com|office\.com|outlook\.office365\.com|teams\.microsoft\.com",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "ssl_sni",
    },
    # ----- Servers -----
    {
        "match_field": "ssl_sni",
        "match_value": r"grafana\.com|gitlab\.|snapcraft\.io|imunify(?:360)?\.com|cloudlinux|cpanel\.|smtp\.gmail\.com",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.85,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"updates?\.paloaltonetworks\.com",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Palo Alto Networks"},
        "weight": 0.9,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"yeastar|pbxsmtp\.com",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Yeastar"},
        "weight": 0.9,
        "evidence_type": "ssl_sni",
    },
    # ----- IoT -----
    {
        "match_field": "ssl_sni",
        "match_value": r"mqtt\.googleapis|iot\.googleapis",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "ssl_sni",
    },
    {
        "match_field": "ssl_sni",
        "match_value": r"\.nest\.com|home\.nest",
        "match_type": "regex",
        "infer": {"device_type": "IoT", "os": None, "os_version": None, "vendor": "Nest"},
        "weight": 0.80,
        "evidence_type": "ssl_sni",
    },
]

# ---------------------------------------------------------------------------
# HTTP HOST RULES  (http.host from client requests)
# ---------------------------------------------------------------------------

HTTP_HOST_RULES: list[dict] = [
    {
        "match_field": "http_host",
        "match_value": r"events\.data\.microsoft\.com|mobile\.events\.data\.microsoft\.com|settings-win\.data\.microsoft\.com|office\.com|outlook\.office365\.com|teams\.microsoft\.com",
        "match_type": "regex",
        "infer": {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "http_host",
    },
    {
        "match_field": "http_host",
        "match_value": r"grafana\.|gitlab\.|snapcraft\.io|imunify(?:360)?\.com|cloudlinux|cpanel\.|smtp\.gmail\.com|cadvisor\.|node_exporter\.|memcached_exporter\.|prometheus\.|alertmanager\.",
        "match_type": "regex",
        "infer": {"device_type": "Server", "os": None, "os_version": None, "vendor": None},
        "weight": 0.8,
        "evidence_type": "http_host",
    },
    {
        "match_field": "http_host",
        "match_value": r"updates?\.paloaltonetworks\.com",
        "match_type": "regex",
        "infer": {"device_type": "Network", "os": None, "os_version": None, "vendor": "Palo Alto Networks"},
        "weight": 0.85,
        "evidence_type": "http_host",
    },
    {
        "match_field": "http_host",
        "match_value": r"hikvision|hikvisioneurope|\.axis\.com|dahua|lechange\.com",
        "match_type": "regex",
        "infer": {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None},
        "weight": 0.75,
        "evidence_type": "http_host",
    },
]

# ---------------------------------------------------------------------------
# DIRECTION-AWARE PORT BUCKETS
#
# A port in conn.log is the *destination* port (id.resp_p). The asset that
# initiated the flow (id.orig_h) is the CLIENT; the receiver is the SERVER.
# A port like 104 (DICOM) means the responder is an IoMT modality — it does
# NOT mean the client is one. Likewise port 9100 (JetDirect) means the
# responder is a printer.
#
# The classifier consumes two sets per asset:
#   * server_listen_ports  — destination ports observed on this asset
#                            (i.e. flows where this asset was id.resp_h)
#   * client_dst_ports     — destination ports this asset reached out to
#                            (i.e. flows where this asset was id.orig_h)
#
# SERVER_PORT_RULES  — apply to server_listen_ports only.
# CLIENT_PORT_RULES  — apply to client_dst_ports only.
#
# A port number can appear in both lists with different semantics; the
# tables below are deliberately separate to avoid mixing them.
# ---------------------------------------------------------------------------


def _server_port_rule(port: int, label: str, infer: dict, weight: float) -> dict:
    return {
        "match_field": "server_port",
        "match_value": port,
        "match_type": "exact",
        "infer": infer,
        "weight": weight,
        "evidence_type": "server_port",
        "label": label,
    }


def _client_port_rule(port: int, label: str, infer: dict, weight: float) -> dict:
    return {
        "match_field": "client_port",
        "match_value": port,
        "match_type": "exact",
        "infer": infer,
        "weight": weight,
        "evidence_type": "client_port",
        "label": label,
    }


# Ports where the *listener* is the device of interest.
SERVER_PORT_RULES: list[dict] = [
    # ----- IoMT -----
    _server_port_rule(104,   "DICOM",        {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},      0.95),
    _server_port_rule(2575,  "HL7",          {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},      0.90),
    _server_port_rule(11112, "DICOM-TLS",    {"device_type": "IoMT", "os": None, "os_version": None, "vendor": None},      0.95),
    # ----- IP Cameras -----
    _server_port_rule(554,   "RTSP",         {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None}, 0.85),
    _server_port_rule(8554,  "RTSP-alt",     {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None}, 0.65),
    _server_port_rule(37777, "Dahua-RTSP",   {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": "Dahua"}, 0.80),
    _server_port_rule(34567, "DVR-API",      {"device_type": "IP Camera", "os": None, "os_version": None, "vendor": None}, 0.70),
    # ----- Printers -----
    _server_port_rule(9100,  "JetDirect",    {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},   0.95),
    _server_port_rule(631,   "IPP",          {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},   0.90),
    _server_port_rule(515,   "LPD",          {"device_type": "Printer", "os": None, "os_version": None, "vendor": None},   0.90),
    # ----- IoT / OT -----
    _server_port_rule(1883,  "MQTT",         {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},       0.85),
    _server_port_rule(8883,  "MQTT-TLS",     {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},       0.85),
    _server_port_rule(502,   "Modbus",       {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},       0.90),
    _server_port_rule(47808, "BACnet",       {"device_type": "IoT", "os": None, "os_version": None, "vendor": None},       0.90),
    # ----- Network gear -----
    _server_port_rule(161,   "SNMP",         {"device_type": "Network", "os": None, "os_version": None, "vendor": None},   0.70),
    _server_port_rule(179,   "BGP",          {"device_type": "Network", "os": None, "os_version": None, "vendor": None},   0.95),
    _server_port_rule(5060,  "SIP",          {"device_type": "Network", "os": None, "os_version": None, "vendor": None},   0.80),
    _server_port_rule(6831,  "sFlow",        {"device_type": "Network", "os": None, "os_version": None, "vendor": None},   0.75),
    # ----- Workstation/Remote-access (host accepting RDP/VNC = workstation/server) -----
    _server_port_rule(3389,  "RDP",          {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None}, 0.70),
    _server_port_rule(5900,  "VNC",          {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None}, 0.55),
    _server_port_rule(445,   "SMB",          {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None}, 0.55),
    # ----- Servers -----
    _server_port_rule(22,    "SSH",          {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": None}, 0.55),
    _server_port_rule(80,    "HTTP",         {"device_type": "Server", "os": None, "os_version": None, "vendor": None},   0.45),
    _server_port_rule(443,   "HTTPS",        {"device_type": "Server", "os": None, "os_version": None, "vendor": None},   0.45),
    _server_port_rule(2087,  "cPanel SSL",   {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": "cPanel"}, 0.95),
    _server_port_rule(2083,  "cPanel",       {"device_type": "Server", "os": "Linux", "os_version": None, "vendor": "cPanel"}, 0.90),
    _server_port_rule(10051, "Zabbix-Srv",   {"device_type": "Server", "os": None, "os_version": None, "vendor": "Zabbix"}, 0.85),
    _server_port_rule(3306,  "MySQL",        {"device_type": "Server", "os": None, "os_version": None, "vendor": "MySQL"}, 0.85),
    _server_port_rule(5432,  "PostgreSQL",   {"device_type": "Server", "os": None, "os_version": None, "vendor": "PostgreSQL"}, 0.85),
    _server_port_rule(6379,  "Redis",        {"device_type": "Server", "os": None, "os_version": None, "vendor": "Redis"}, 0.85),
    _server_port_rule(27017, "MongoDB",      {"device_type": "Server", "os": None, "os_version": None, "vendor": "MongoDB"}, 0.85),
    _server_port_rule(9200,  "Elastic",      {"device_type": "Server", "os": None, "os_version": None, "vendor": "Elastic"}, 0.85),
    _server_port_rule(25,    "SMTP",         {"device_type": "Server", "os": None, "os_version": None, "vendor": None},   0.70),
    _server_port_rule(53,    "DNS-Srv",      {"device_type": "Server", "os": None, "os_version": None, "vendor": None},   0.55),
]

# Ports a *client* contacts that strongly imply what the client itself is.
CLIENT_PORT_RULES: list[dict] = [
    # NetBIOS / SMB chatter is overwhelmingly Windows workstation behavior
    _client_port_rule(137, "NetBIOS-NS", {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None}, 0.55),
    _client_port_rule(138, "NetBIOS-DG", {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None}, 0.55),
    _client_port_rule(5355, "LLMNR",     {"device_type": "Workstation", "os": "Windows", "os_version": None, "vendor": None}, 0.55),
    # DHCP client port — anything that runs DHCP-client at scale is generally an endpoint
    _client_port_rule(67, "DHCP-Srv",    {"device_type": "Workstation", "os": None, "os_version": None, "vendor": None},     0.40),
    # Printer-discovery from a workstation toward a printer => the *server* is a printer.
    # That goes in SERVER_PORT_RULES already; nothing to add here.
]


# Backwards-compatible PORT_RULES alias — older code paths read this.
# It points at SERVER_PORT_RULES because that was the original (correct)
# semantic for everything the legacy classifier matched against.
PORT_RULES: list[dict] = SERVER_PORT_RULES


# ---------------------------------------------------------------------------
# ALL RULES — convenience aggregate
# ---------------------------------------------------------------------------

ALL_RULES: list[dict] = (
    SERVER_PORT_RULES + CLIENT_PORT_RULES
    + DHCP_RULES + USER_AGENT_RULES + JA3_CATEGORY_RULES + JA3S_CATEGORY_RULES
    + VENDOR_RULES + HOSTNAME_RULES + DNS_RULES + SNI_RULES + HTTP_HOST_RULES
)
