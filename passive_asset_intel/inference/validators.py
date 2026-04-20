"""Small pure-function validators used by the classifier and engine.

Every function is total (never raises) and idempotent. They exist to strip
corrupted / empty signals at the edge so the classifier core only sees
well-shaped data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Iterable

# ── MAC addresses ──────────────────────────────────────────────
# Accepts the common forms: AA:BB:CC:DD:EE:FF, aa-bb-..., aabb.ccdd.eeff,
# and the internal placeholder "ip:<addr>" that conn_parser uses when no
# real L2 address was seen.
_MAC_RE = re.compile(
    r"^(?:"
    r"[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}"
    r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"
    r"|[0-9A-Fa-f]{12}"
    r")$"
)
_IP_PLACEHOLDER_PREFIX = "ip:"


def is_real_mac(mac: str | None) -> bool:
    """True only for a syntactically valid Ethernet MAC (not the ip: stub)."""
    if not isinstance(mac, str) or not mac:
        return False
    if mac.startswith(_IP_PLACEHOLDER_PREFIX):
        return False
    return bool(_MAC_RE.match(mac.strip()))


def normalize_mac(mac: str | None) -> str | None:
    """Return a canonical ``aa:bb:cc:dd:ee:ff`` form, or ``None``."""
    if not is_real_mac(mac):
        return None
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    if len(hex_only) != 12:
        return None
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


# ── IP addresses ───────────────────────────────────────────────
def is_valid_ip(value: str | None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ── Ports ──────────────────────────────────────────────────────
def sanitize_port_set(values: Iterable[object] | None) -> set[int]:
    """Keep only 1..65535 integer ports; silently drop everything else."""
    if not values:
        return set()
    out: set[int] = set()
    for v in values:
        try:
            n = int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535:
            out.add(n)
    return out


# ── Fingerprint hashes (JA3/JA3S) ──────────────────────────────
_JA3_RE = re.compile(r"^[0-9a-f]{32}$")


def is_valid_ja3(value: object) -> bool:
    """True for a 32-char lowercase hex MD5 — the JA3/JA3S wire format."""
    return isinstance(value, str) and bool(_JA3_RE.match(value.strip().lower()))


def sanitize_hash_set(values: Iterable[object] | None) -> set[str]:
    """Keep only well-formed JA3/JA3S hashes, lower-cased."""
    if not values:
        return set()
    out: set[str] = set()
    for v in values:
        if is_valid_ja3(v):
            out.add(v.strip().lower())  # type: ignore[union-attr]
    return out


# ── Free-text signals ──────────────────────────────────────────
_MAX_TEXT_LEN = 512


def sanitize_text_list(values: Iterable[object] | None) -> list[str]:
    """Strip, dedup (preserving first occurrence), cap length, drop empties."""
    if not values:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if not isinstance(v, str):
            continue
        s = v.strip()
        if not s:
            continue
        if len(s) > _MAX_TEXT_LEN:
            s = s[:_MAX_TEXT_LEN]
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# ── Identity fingerprinting ────────────────────────────────────
# Used by the identity engine to detect duplicate assets that share
# behavioral signals (JA3, DNS domains, User-Agents) but have different
# MAC/IP keys.

_IDENTITY_TOP_N_DNS = 10  # keep only top N sorted domains


def compute_identity_fingerprint(
    ja3_set: set[str],
    dns_domains: list[str],
    user_agents: list[str],
) -> str | None:
    """Compute a stable SHA-256 fingerprint from behavioural signals.

    Returns None if there are no usable signals (merging would be meaningless).
    The fingerprint is deterministic: same inputs always produce the same hash,
    regardless of collection order.

    Args:
        ja3_set: Set of validated JA3 hashes (lowercase hex).
        dns_domains: List of DNS query domains.
        user_agents: List of HTTP User-Agent strings.

    Returns:
        Hex SHA-256 digest, or None if insufficient signals.
    """
    parts: list[str] = []

    # JA3 fingerprints — sorted for determinism
    sorted_ja3 = sorted(ja3_set)
    if sorted_ja3:
        parts.append("ja3:" + ",".join(sorted_ja3))

    # Top DNS domains — extract base domain, sort, dedup
    dns_bases: set[str] = set()
    for domain in dns_domains:
        if not isinstance(domain, str) or not domain:
            continue
        # Extract base domain (last 2 labels): "a.b.example.com" → "example.com"
        labels = domain.strip().rstrip(".").lower().split(".")
        if len(labels) >= 2:
            dns_bases.add(".".join(labels[-2:]))
        elif labels:
            dns_bases.add(labels[0])
    sorted_dns = sorted(dns_bases)[:_IDENTITY_TOP_N_DNS]
    if sorted_dns:
        parts.append("dns:" + ",".join(sorted_dns))

    # User-Agent — sorted, deduplicated
    ua_set: set[str] = set()
    for ua in user_agents:
        if isinstance(ua, str) and ua.strip():
            ua_set.add(ua.strip().lower())
    sorted_ua = sorted(ua_set)
    if sorted_ua:
        parts.append("ua:" + ",".join(sorted_ua))

    if not parts:
        return None

    combined = "|".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()
