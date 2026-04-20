"""Extract OS / product versions from passive signals.

The device classifier already figures out *which* OS an asset runs; this
module adds the second-order signal — which version. That matters for CVE
matching: a blanket CPE ``cpe:2.3:o:microsoft:windows:*:...`` matches every
Windows CVE ever published, while ``cpe:2.3:o:microsoft:windows_10:*:...``
is narrow enough to be actionable.

We only extract versions we can map with high confidence to a CPE segment.
Probabilistic guesses would poison the CVE feed.
"""

from __future__ import annotations

import re
from typing import Iterable

# Windows NT kernel version → marketing product name used by NVD.
# Keys are the raw numbers that appear in User-Agent "Windows NT X.Y".
_WINDOWS_NT_MAP: dict[str, tuple[str, str]] = {
    "10.0": ("Windows 10", "10"),   # NVD has both windows_10 and windows_11 — 11 is indistinguishable in UA, treat as 10
    "6.3":  ("Windows 8.1", "6.3"),
    "6.2":  ("Windows 8", "6.2"),
    "6.1":  ("Windows 7", "6.1"),
    "6.0":  ("Windows Vista", "6.0"),
    "5.2":  ("Windows Server 2003", "5.2"),
    "5.1":  ("Windows XP", "5.1"),
}

_WINDOWS_NT_RE = re.compile(r"Windows NT (\d+\.\d+)", re.IGNORECASE)
_ANDROID_RE = re.compile(r"Android[ /](\d+)(?:\.(\d+))?", re.IGNORECASE)
_MAC_OS_RE = re.compile(r"Mac OS X (\d+)[._](\d+)(?:[._](\d+))?", re.IGNORECASE)
_UBUNTU_RE = re.compile(r"Ubuntu[/ ](\d+\.\d+)", re.IGNORECASE)


def extract_os_version(
    user_agents: Iterable[str],
    dhcp_vendors: Iterable[str] | None = None,
) -> tuple[str | None, str | None]:
    """Return (os_name, os_version) extracted from passive evidence.

    The matching is greedy — we stop on the first pattern that fits. Order
    reflects signal reliability: Windows NT > Android > macOS > Ubuntu DHCP.

    Returns (None, None) when nothing usable is found. Callers treat the
    returned OS name as a *suggestion* — the rule engine's verdict still
    wins for device_type / vendor.
    """
    for ua in user_agents:
        if not isinstance(ua, str):
            continue

        m = _WINDOWS_NT_RE.search(ua)
        if m:
            nt = m.group(1)
            mapped = _WINDOWS_NT_MAP.get(nt)
            if mapped:
                return mapped

        m = _ANDROID_RE.search(ua)
        if m:
            major = m.group(1)
            return ("Android", major)

        m = _MAC_OS_RE.search(ua)
        if m:
            major = m.group(1)
            minor = m.group(2)
            return ("macOS", f"{major}.{minor}")

        m = _UBUNTU_RE.search(ua)
        if m:
            return ("Ubuntu Linux", m.group(1))

    for dv in dhcp_vendors or []:
        if not isinstance(dv, str):
            continue
        m = _UBUNTU_RE.search(dv)
        if m:
            return ("Ubuntu Linux", m.group(1))

    return (None, None)
