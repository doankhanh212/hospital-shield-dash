"""Categorizer — pure transformation layer for feature preprocessing.

Maps raw signal values to semantic categories before classification:

*   **Ports → service groups** : e.g. port 104 → ``"medical"``, port 9100 → ``"printing"``
*   **DNS domains → categories** : e.g. ``windowsupdate.com`` → ``"os_update"``
*   **JA3 hashes → TLS stack categories** : e.g. known Chrome hash → ``"modern_browser"``

This is a dimensionality-reduction step that enriches the feature dict.
Existing raw fields are preserved — the categorizer ADDS new fields, never
removes old ones.  The classifier can use either raw or categorized data.
"""

from __future__ import annotations

import re

# ────────────────────────────────────────────────────────────────────────
# Port → service group
# ────────────────────────────────────────────────────────────────────────

PORT_SERVICE_GROUPS: dict[str, set[int]] = {
    "medical":       {104, 2575, 2761, 11112},
    "camera":        {554, 8554, 37777, 34567},
    "printing":      {515, 631, 9100},
    "iot":           {502, 1883, 8883, 47808},
    "network_mgmt":  {161, 179, 5060, 6831},
    "remote_access": {3389, 5900},
    "file_sharing":  {137, 138, 139, 445},
    "web":           {80, 443, 8080, 8443},
    "database":      {3306, 5432, 6379, 27017, 9200},
    "mail":          {25, 110, 143, 465, 587, 993, 995},
    "dns":           {53, 5353},
}

# Reverse lookup: port → group name (built once at import time)
_PORT_TO_GROUP: dict[int, str] = {}
for _grp, _ports in PORT_SERVICE_GROUPS.items():
    for _p in _ports:
        _PORT_TO_GROUP[_p] = _grp


def categorize_ports(ports: set[int]) -> set[str]:
    """Map a set of ports to their service group names."""
    return {_PORT_TO_GROUP[p] for p in ports if p in _PORT_TO_GROUP}


# ────────────────────────────────────────────────────────────────────────
# DNS domain → category
# ────────────────────────────────────────────────────────────────────────

DNS_CATEGORY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "os_update": [
        re.compile(r"windowsupdate\.com", re.I),
        re.compile(r"\.update\.microsoft\.com", re.I),
        re.compile(r"\.ubuntu\.com", re.I),
        re.compile(r"\.debian\.org", re.I),
        re.compile(r"\.fedoraproject\.org", re.I),
        re.compile(r"\.apple\.com.*swupdate", re.I),
    ],
    "cloud_infra": [
        re.compile(r"googleapis\.com", re.I),
        re.compile(r"amazonaws\.com", re.I),
        re.compile(r"\.azure\.", re.I),
        re.compile(r"\.cloudflare\.com", re.I),
        re.compile(r"\.akamaized\.net", re.I),
    ],
    "medical": [
        re.compile(r"epic\.com", re.I),
        re.compile(r"cerner\.com", re.I),
        re.compile(r"hl7\.org", re.I),
        re.compile(r"meditech\.com", re.I),
        re.compile(r"allscripts\.com", re.I),
    ],
    "surveillance": [
        re.compile(r"hikvision", re.I),
        re.compile(r"dahua", re.I),
        re.compile(r"axis\.com", re.I),
        re.compile(r"uniview", re.I),
    ],
    "endpoint_security": [
        re.compile(r"symantec", re.I),
        re.compile(r"kaspersky", re.I),
        re.compile(r"mcafee", re.I),
        re.compile(r"avast", re.I),
        re.compile(r"bitdefender", re.I),
        re.compile(r"sophos", re.I),
        re.compile(r"crowdstrike", re.I),
    ],
    "printing": [
        re.compile(r"hp\.com.*print", re.I),
        re.compile(r"cups", re.I),
        re.compile(r"xerox\.com", re.I),
    ],
    "iot_home": [
        re.compile(r"tuya", re.I),
        re.compile(r"smartthings", re.I),
        re.compile(r"nest\.com", re.I),
    ],
    "browser_telemetry": [
        re.compile(r"safebrowsing", re.I),
        re.compile(r"telemetry.*mozilla", re.I),
    ],
    "cdn": [
        re.compile(r"cloudfront\.net", re.I),
        re.compile(r"fastly\.net", re.I),
        re.compile(r"edgecast", re.I),
    ],
}


def categorize_dns(domains: list[str]) -> set[str]:
    """Map a list of DNS query domains to category names."""
    categories: set[str] = set()
    for domain in domains:
        if not isinstance(domain, str):
            continue
        for cat, patterns in DNS_CATEGORY_PATTERNS.items():
            for pat in patterns:
                if pat.search(domain):
                    categories.add(cat)
                    break
    return categories


# ────────────────────────────────────────────────────────────────────────
# JA3 hash → TLS client-stack category  (CLIENT role only)
# ────────────────────────────────────────────────────────────────────────
# Built from dataset frequency analysis (2026-04-16):
#   Top-7 hashes cover 53% of all JA3 rows (4,413 / 8,635).
#   Top-20 cover 57%.  Remaining → "unknown".
#
# Methodology: cross-referenced against ja3er.com and Zeek community
# databases.  Hashes seen on 2,400 assets (generic VPS TLS) are
# deliberately "openssl_default" — they describe the *library*, not a
# device type, and carry LOW weight in rules.
#
# IMPORTANT: these are BEHAVIOR signals.  Never use for identity/merge.

JA3_CATEGORY_MAP: dict[str, str] = {
    # ── openssl_default (generic Linux/VPS — massively shared) ─────
    "0149f47eabf9a20d0893e2a44e5a6323": "openssl_default",   # cnt=2400 — most common, generic OpenSSL 1.1+
    "1ce565f411fbc7412e3c5ba0bcfd62ab": "openssl_default",   # cnt=172

    # ── chrome_tls (Chromium-based browsers) ──────────────────────
    "8bd06f4341a65d44a68bd2cef7cbedc6": "chrome_tls",        # cnt=916 — Chrome 90+ / Edge / Brave
    "e7d705a3286e19ea42f587b344ee6865": "chrome_tls",        # cnt=16 — Chrome 80-89

    # ── firefox_tls ────────────────────────────────────────────────
    "479b976148ec2a1a195ae2e15805fefa": "firefox_tls",       # cnt=278 — Firefox 90+
    "839bbe3ed07fed922ded5ac83a2ab634": "firefox_tls",       # historical FF

    # ── edge_tls (Edge-specific when distinguishable) ─────────────
    "473cd7cb9faa642487833865d516e578": "edge_tls",          # cnt=247 — Edge on Windows 11
    "b32309a26951912be7dba376398abc3b": "edge_tls",          # Edge variant

    # ── windows_native_tls (SChannel / WinHTTP / .NET) ────────────
    "73ede1f461b6cdf3d49a8cc100f64a9e": "windows_native_tls",  # cnt=204 — WinHTTP / SChannel
    "1449472ba4c4ddb602762f628f080be4": "windows_native_tls",  # cnt=196 — .NET / PowerShell
    "a0e9f5d64349fb13191bc781f81f42e1": "windows_native_tls",  # cnt=16 — Windows 10 built-in

    # ── curl_cli (curl / wget / libcurl) ──────────────────────────
    "29a483aa2a7106f73d1228c2e68a3f84": "curl_cli",          # cnt=61 — curl 7.x with OpenSSL
    "de9f2c7fd25e1b3afad3e85a0226b907": "curl_cli",          # known curl/libcurl

    # ── python_requests (Python urllib3 / requests / httpx) ───────
    "0874ee7f01de5a3e377d931eec2228a6": "python_requests",   # cnt=59 — Python 3.10+ ssl
    "7c02dbae662670040c7af9bd15fb7e2f": "python_requests",   # Python requests/urllib3

    # ── java_tls (JDK / Android / Kotlin) ─────────────────────────
    "a1180b5557791f9d36d36739d0d9b08a": "java_tls",          # cnt=56 — Java 11+ TLS
    "91f068be9e8819ee72e86f0b1b1a6bf0": "java_tls",          # Java 8/9
    "773906b0efdefa24a7f2b8eb6985bf37": "java_tls",          # cnt=42 — Android/Java variant

    # ── go_tls (Go stdlib crypto/tls) ─────────────────────────────
    "b4da7f95e46bf2cf5285fd609cf726e4": "go_tls",            # cnt=48 — Go 1.18+
    "b6b4e73f44e0b0f9e5abf9e3e3e5e3b0": "go_tls",            # Go variant

    # ── iot_embedded_tls (MbedTLS / WolfSSL / BearSSL / tiny stacks)
    "d7a2543716f784e8de73ffe3f7f6234b": "iot_embedded_tls",  # cnt=43 — MbedTLS (common on IoT)
    "e4228d1fa6f13a432e4bc5ff54841b91": "iot_embedded_tls",  # cnt=39 — WolfSSL
    "f5bd742fa88333052a1deec09f821012": "iot_embedded_tls",  # cnt=37 — BearSSL/embedded

    # ── medical_device_tls (vendor-specific medical TLS stacks) ───
    "ecdf4f49dd59effc439639da29186671": "medical_device_tls",  # cnt=36 — GE Healthcare
    "f17ca639ecdcaa65b4521c49e3515ef9": "medical_device_tls",  # cnt=34 — Philips/Siemens

    # ── node_tls (Node.js / Electron) ─────────────────────────────
    "095a9cdf6fceacc9c38736015b7d1ec4": "node_tls",          # cnt=29 — Node.js 16+
    "c199b43d41b470f8f68c5561f8f1ce3e": "node_tls",          # cnt=26 — Electron
}

# Reverse: category → set of hashes
JA3_CATEGORIES: dict[str, set[str]] = {}
for _hash, _cat in JA3_CATEGORY_MAP.items():
    JA3_CATEGORIES.setdefault(_cat, set()).add(_hash)


def categorize_ja3(hashes: set[str]) -> set[str]:
    """Map a set of JA3 hashes to TLS client-stack category names.

    Hashes not in the map are silently dropped (caller treats absence
    as 'unknown' via the has_unknown_ja3 flag).
    """
    return {JA3_CATEGORY_MAP[h] for h in hashes if h in JA3_CATEGORY_MAP}


def get_ja3_category(h: str) -> str:
    """Return the category for a single JA3 hash, or 'unknown'."""
    return JA3_CATEGORY_MAP.get(h, "unknown")


# ────────────────────────────────────────────────────────────────────────
# JA3S hash → TLS server-stack category  (SERVER role only)
# ────────────────────────────────────────────────────────────────────────
# Built from dataset JA3S frequency analysis (285 total rows).
# JA3S identifies the *server* TLS implementation responding to clients.

JA3S_CATEGORY_MAP: dict[str, str] = {
    # ── nginx (OpenResty / nginx with OpenSSL) ────────────────────
    "907bf3ecef1c987c889946b737b43de8": "nginx",         # cnt=37 — most common
    "15af977ce25de452b96affa2addb1036": "nginx",         # cnt=33

    # ── apache (Apache httpd with OpenSSL / mod_ssl) ──────────────
    "2b0648ab686ee45e0e7c35fcfb0eea7e": "apache",        # cnt=33

    # ── cloudflare (CDN edge — not the origin server) ─────────────
    "f4febc55ea12b31ae17cfb7e614afda8": "cloudflare",    # cnt=16

    # ── iis (Microsoft IIS / SChannel) ────────────────────────────
    "ae4edc6faf64d08308082ad26be60767": "iis",           # cnt=5
    "46ca3a127f5443353dfb8cc2e16197e5": "iis",           # cnt=18

    # ── litespeed / cPanel (LiteSpeed + cPanel hosting) ───────────
    "eb1d94daa7e0344597e756a1fb6e7054": "litespeed",     # cnt=12
    "2fe9b0e731d3d41b2b84e8e1d6186836": "litespeed",     # cnt=12

    # ── generic_server (OpenSSL server but unclassified) ──────────
    "303951d4c50efb2e991652225a6f02b1": "generic_server",  # cnt=8
    "2253c82f03b621c5144709b393fde2c9": "generic_server",  # cnt=7
    "bcf3a836c82d12ee988005fb0c011445": "generic_server",  # cnt=3

    # ── embedded_tls (tiny TLS stacks — IoT/camera/printer) ───────
    "475c9302dc42b2751db9edcac3b74891": "embedded_tls",  # cnt=5
    "17e97216fa7f4ec8c43090c6eed97c25": "embedded_tls",  # cnt=4
    "986571066668055ae9481cb84fda634a": "embedded_tls",  # cnt=3
    "50a9e7b112931e541503e8a2499252b9": "embedded_tls",  # cnt=3
}

JA3S_CATEGORIES: dict[str, set[str]] = {}
for _hash, _cat in JA3S_CATEGORY_MAP.items():
    JA3S_CATEGORIES.setdefault(_cat, set()).add(_hash)


def categorize_ja3s(hashes: set[str]) -> set[str]:
    """Map a set of JA3S hashes to TLS server-stack category names."""
    return {JA3S_CATEGORY_MAP[h] for h in hashes if h in JA3S_CATEGORY_MAP}


def get_ja3s_category(h: str) -> str:
    """Return the category for a single JA3S hash, or 'unknown'."""
    return JA3S_CATEGORY_MAP.get(h, "unknown")


# ────────────────────────────────────────────────────────────────────────
# JA3 category → human-readable behavior label
# ────────────────────────────────────────────────────────────────────────

BEHAVIOR_LABEL_MAP: dict[str, str] = {
    # Browsers → User Browsing
    "chrome_tls":         "User Browsing",
    "firefox_tls":        "User Browsing",
    "edge_tls":           "User Browsing",
    # CLI / scripting tools → Automation / Script
    "curl_cli":           "Automation / Script",
    "python_requests":    "Automation / Script",
    "go_tls":             "Automation / Script",
    "node_tls":           "Automation / Script",
    # Java runtime → Backend Service
    "java_tls":           "Backend Service",
    # Windows built-in TLS → Windows Service
    "windows_native_tls": "Windows Service",
    # OpenSSL default → Generic Client
    "openssl_default":    "Generic Client",
    # Embedded / IoT stacks → Embedded Device
    "iot_embedded_tls":   "Embedded Device",
    # Medical device stacks → Medical Device
    "medical_device_tls": "Medical Device",
}


def get_behavior_type(ja3_categories: set[str]) -> str:
    """Derive a single behavior label from a set of JA3 categories.

    Priority: Medical Device > Embedded Device > User Browsing >
    Automation / Script > Backend Service > Windows Service > Generic Client.
    If no category maps, returns 'Unknown'.
    """
    _PRIORITY = [
        "Medical Device",
        "Embedded Device",
        "User Browsing",
        "Automation / Script",
        "Backend Service",
        "Windows Service",
        "Generic Client",
    ]
    labels = {BEHAVIOR_LABEL_MAP[c] for c in ja3_categories if c in BEHAVIOR_LABEL_MAP}
    if not labels:
        return "Unknown"
    for lbl in _PRIORITY:
        if lbl in labels:
            return lbl
    return "Unknown"


# ────────────────────────────────────────────────────────────────────────
# Unified feature enrichment
# ────────────────────────────────────────────────────────────────────────


def categorize_features(features: dict) -> dict:
    """Enrich a feature dict with categorized fields.

    This is a pure function — the input dict is NOT mutated; a new dict
    is returned with both the original and categorized fields.
    """
    enriched = dict(features)

    # Port service groups (role-aware)
    enriched["client_port_groups"] = categorize_ports(
        features.get("client_dst_ports") or set()
    )
    enriched["server_port_groups"] = categorize_ports(
        features.get("server_listen_ports") or set()
    )

    # DNS domain categories
    enriched["dns_categories"] = categorize_dns(
        features.get("dns_queries") or []
    )

    # JA3 TLS client-stack categories
    client_ja3 = features.get("client_ja3") or set()
    enriched["ja3_categories"] = categorize_ja3(client_ja3)
    enriched["has_tls_client"] = len(client_ja3) > 0

    # JA3S TLS server-stack categories
    server_ja3s = features.get("server_ja3s") or set()
    enriched["ja3s_categories"] = categorize_ja3s(server_ja3s)
    enriched["has_tls_server"] = len(server_ja3s) > 0

    # Flag unknown hashes (present but not in map)
    enriched["has_unknown_ja3"] = bool(client_ja3 - set(JA3_CATEGORY_MAP))
    enriched["has_unknown_ja3s"] = bool(server_ja3s - set(JA3S_CATEGORY_MAP))

    # Behavior label derived from JA3 categories
    enriched["behavior_type"] = get_behavior_type(enriched["ja3_categories"])

    return enriched
