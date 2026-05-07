"""NVD integration service — fetch CVE data from NVD API v2.0.

Maps CPE strings from inference_results to known CVEs and populates
the ``vulnerabilities`` and ``asset_vulnerabilities`` tables.

NVD API v2.0 documentation:
    https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds

Reliability features:
    - Retry with exponential backoff on 429 / 5xx errors
    - In-memory CPE→CVE cache to avoid redundant API calls
    - Structured logging for every request outcome
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import httpx

from passive_asset_intel.utils.logger import setup_logger

logger = setup_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Delay between NVD API calls to respect rate limits
DELAY_WITH_KEY = 0.6     # 50 req / 30s
DELAY_WITHOUT_KEY = 6.0  # 5 req / 30s

# Retry settings
_MAX_RETRIES = 3
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

# CVE date-window policy
# ───────────────────────────────────────────────────────────────────────────
# NVD API caps each date-filtered query at a 120-day window, so we have to
# chunk. To avoid flooding the analyst with thousands of old CVEs we only
# look at CVEs published from CVE_HORIZON_START onward.
CVE_HORIZON_START = datetime(2022, 1, 1, tzinfo=timezone.utc)
# Window slightly under NVD's 120-day cap for safety.
NVD_WINDOW_DAYS = 119
# Hard cap per CPE to keep the UI usable — prioritise newest CVEs first.
MAX_CVES_PER_CPE = 200

# In-memory cache: CPE string → list of CVE dicts (survives across sync calls
# within the same process lifetime, cleared on restart)
_cpe_cache: dict[str, list[dict[str, Any]]] = {}


async def get_nvd_config(pool: asyncpg.Pool) -> dict | None:
    """Retrieve the stored NVD integration config."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT api_key, config, last_sync_at FROM integrations WHERE name = 'nvd'"
        )
        if not row:
            return None
        return {
            "api_key": row["api_key"],
            "config": row["config"],
            "last_sync_at": row["last_sync_at"],
        }


async def save_nvd_config(pool: asyncpg.Pool, api_key: str) -> None:
    """Store or update the NVD API key."""
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO integrations (id, name, api_key, created_at, updated_at)
            VALUES ($1, 'nvd', $2, NOW(), NOW())
            ON CONFLICT (name) DO UPDATE
                SET api_key = EXCLUDED.api_key,
                    updated_at = NOW()
        """, uuid.uuid4(), api_key)


async def sync_nvd_for_all_cpes(
    pool: asyncpg.Pool,
    *,
    max_cpes: int | None = None,
    test_mode: bool = False,
) -> dict:
    """Fetch CVEs from NVD for all unique CPEs found in inference_results.

    1. Gather distinct CPEs from inference_results.
    2. For each CPE, query the NVD API.
    3. Upsert into vulnerabilities table.
    4. Link to assets via asset_vulnerabilities.

    Args:
        pool: asyncpg connection pool
        max_cpes: if set, only query up to this many CPEs (for the Test button —
                  a full sync can take minutes; the test samples the first N).
        test_mode: when True, only queries the most recent 120-day window and
                   caps CVEs at 30 per CPE so the Test button finishes inside
                   the 90s UI timeout.

    Returns:
        Summary dict with counts and sample CVE list (up to 10 items).
    """
    started_at = datetime.now(timezone.utc)
    nvd_config = await get_nvd_config(pool)
    api_key = nvd_config["api_key"] if nvd_config else None
    delay = DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY

    # Fetch unique CPEs along with each asset's inferred os_version so the
    # link pass can prune CVEs whose versionStart/End range doesn't cover
    # the asset (a Windows 10 host should not inherit Windows 7-specific
    # CVEs even though both CPEs share the ``microsoft:windows`` prefix).
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT cpe, asset_id::text, os_version
            FROM inference_results
            WHERE cpe IS NOT NULL AND cpe != ''
        """)

    if not rows:
        return {
            "cpes_checked": 0,
            "cves_found": 0,
            "assets_linked": 0,
            "elapsed_seconds": 0.0,
            "sample_cves": [],
            "total_cpes": 0,
            "api_key_used": bool(api_key),
        }

    # Group assets by CPE — each entry is (asset_id, os_version) so the
    # link pass can apply per-asset version filtering.
    cpe_to_assets: dict[str, list[tuple[str, str | None]]] = {}
    for r in rows:
        cpe = r["cpe"]
        cpe_to_assets.setdefault(cpe, []).append((r["asset_id"], r["os_version"]))

    total_cpes = len(cpe_to_assets)

    # Order CPEs so the most widely-deployed ones are probed first. This
    # matters for the Test button: a 3-CPE sample should hit high-signal
    # software (Windows, Linux, OpenSSH) rather than niche vendor-only CPEs
    # that NVD has no CVEs for.
    sorted_items = sorted(
        cpe_to_assets.items(),
        key=lambda kv: len(kv[1]),
        reverse=True,
    )

    # If max_cpes is set (Test button), take the top N CPEs by asset count.
    if max_cpes is not None and max_cpes > 0:
        cpe_items = sorted_items[:max_cpes]
    else:
        cpe_items = sorted_items

    total_cves = 0
    total_linked = 0
    cpes_checked = 0
    sample_cves: list[dict] = []

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    # Test mode: only probe the last 120 days and cap per CPE for speed.
    if test_mode:
        fetch_horizon = datetime.now(timezone.utc) - timedelta(days=NVD_WINDOW_DAYS)
        fetch_cap = 30
    else:
        fetch_horizon = CVE_HORIZON_START
        fetch_cap = MAX_CVES_PER_CPE

    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        for cpe_str, asset_ids in cpe_items:
            try:
                cves = await _fetch_cves_for_cpe(
                    client,
                    cpe_str,
                    horizon_start=fetch_horizon,
                    max_cves=fetch_cap,
                    delay_between_windows=delay,
                )
                cpes_checked += 1

                for cve_data in cves:
                    # Pre-check: if no (asset_id, version) pair in the
                    # group is actually covered by this CVE's cpeMatch
                    # ranges, don't even upsert the vulnerability row.
                    # Keeps the vulnerabilities table focused on CVEs that
                    # matter to at least one real asset.
                    applicable_assets = [
                        (aid, ver)
                        for aid, ver in asset_ids
                        if _cve_applies_to_asset(
                            cve_data.get("cpe_matches", []),
                            cpe_str,
                            ver,
                        )
                    ]
                    if not applicable_assets:
                        continue

                    vuln_id = await _upsert_vulnerability(pool, cve_data, cpe_str)
                    if vuln_id:
                        total_cves += 1
                        if len(sample_cves) < 10:
                            sample_cves.append({
                                "cve_id": cve_data["cve_id"],
                                "cvss_score": cve_data["cvss_score"],
                                "severity": cve_data["severity"],
                                "cpe": cpe_str,
                                "published": (cve_data.get("published") or "")[:10],
                            })
                        for asset_id, _ver in applicable_assets:
                            linked = await _link_asset_vulnerability(pool, asset_id, vuln_id)
                            if linked:
                                total_linked += 1

                # Respect rate limits
                await asyncio.sleep(delay)

            except Exception:
                logger.exception("NVD fetch failed for CPE", extra={"cpe": cpe_str})
                continue

    # Generate alerts for newly linked vulnerabilities
    alerts_created = await _generate_vuln_alerts(pool)

    # Update last sync timestamp (only for full sync, not test mode)
    if max_cpes is None:
        async with pool.acquire() as conn:
            await conn.execute("""
                UPDATE integrations SET last_sync_at = NOW(), updated_at = NOW()
                WHERE name = 'nvd'
            """)

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    logger.info(
        "NVD sync complete",
        extra={
            "cpes_checked": cpes_checked,
            "cves_found": total_cves,
            "assets_linked": total_linked,
            "elapsed_seconds": elapsed,
            "test_mode": max_cpes is not None,
        },
    )

    return {
        "cpes_checked": cpes_checked,
        "cves_found": total_cves,
        "assets_linked": total_linked,
        "alerts_created": alerts_created,
        "elapsed_seconds": round(elapsed, 2),
        "sample_cves": sample_cves,
        "total_cpes": total_cpes,
        "api_key_used": bool(api_key),
    }


async def _generate_vuln_alerts(pool: asyncpg.Pool) -> int:
    """Create alert rows for asset↔vulnerability links that don't yet have one.

    Maps CVSS → alert severity and uses metadata={cve_id, vulnerability_id}
    for deduplication (so re-running won't duplicate alerts).
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT av.asset_id::text AS asset_id,
                       av.vulnerability_id::text AS vulnerability_id,
                       v.cve_id,
                       v.cvss_score,
                       v.severity,
                       v.description,
                       COALESCE(host(ai.ip_address)::text, '') AS ip
                FROM asset_vulnerabilities av
                JOIN vulnerabilities v ON v.id = av.vulnerability_id
                LEFT JOIN asset_ips ai ON ai.asset_id = av.asset_id AND ai.is_primary = true
                WHERE NOT EXISTS (
                    SELECT 1 FROM alerts a
                    WHERE a.alert_type = 'vulnerability'
                      AND a.asset_id = av.asset_id
                      AND a.metadata->>'vulnerability_id' = av.vulnerability_id::text
                )
            """)

            if not rows:
                return 0

            alert_rows = []
            for r in rows:
                score = float(r["cvss_score"] or 0)
                if score >= 9.0:
                    sev = "Critical"
                elif score >= 7.0:
                    sev = "High"
                elif score >= 4.0:
                    sev = "Medium"
                else:
                    sev = "Low"

                desc = (r["description"] or "").strip().replace("\n", " ")
                if len(desc) > 200:
                    desc = desc[:200] + "..."
                msg = f"{r['cve_id']} (CVSS {score:.1f}): {desc}" if desc else f"{r['cve_id']} (CVSS {score:.1f})"

                alert_rows.append((
                    uuid.uuid4(),
                    "vulnerability",
                    sev,
                    msg,
                    r["ip"] or None,
                    uuid.UUID(r["asset_id"]),
                    json.dumps({
                        "cve_id": r["cve_id"],
                        "vulnerability_id": r["vulnerability_id"],
                        "cvss_score": score,
                    }),
                ))

            await conn.executemany("""
                INSERT INTO alerts (id, alert_type, severity, message,
                                    source_ip, asset_id, metadata,
                                    status, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'new', NOW(), NOW())
            """, alert_rows)

            logger.info("Vulnerability alerts created", extra={"count": len(alert_rows)})
            return len(alert_rows)
    except Exception:
        logger.exception("Failed to generate vulnerability alerts")
        return 0


def _compare_versions(a: str, b: str) -> int:
    """Compare two dotted-numeric version strings.

    Returns -1 / 0 / 1 mimicking ``cmp``. Non-numeric segments compare
    lexicographically as a fallback — NVD versions are almost always numeric
    (``10.0.19041``, ``6.1``, ``13``) so this is mostly exercised on the
    happy path.
    """
    def parts(v: str) -> list:
        out: list = []
        for seg in (v or "").split("."):
            try:
                out.append((0, int(seg)))
            except ValueError:
                out.append((1, seg.lower()))
        return out

    pa, pb = parts(a), parts(b)
    # Pad the shorter list with zeros so "10" == "10.0" and "10" < "10.1".
    width = max(len(pa), len(pb))
    pa += [(0, 0)] * (width - len(pa))
    pb += [(0, 0)] * (width - len(pb))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def _cpe_product_prefix(cpe_str: str) -> str | None:
    """Return ``cpe:2.3:<part>:<vendor>:<product>`` prefix for matching.

    Two CPEs describe the same product when this prefix matches — the
    segments after ``product`` (version/update/edition/...) are what the
    range filter discriminates on.
    """
    parts = cpe_str.split(":")
    if len(parts) < 5 or parts[0] != "cpe":
        return None
    return ":".join(parts[:5])


def _cpe_match_applies(
    match: dict[str, Any],
    asset_cpe: str,
    asset_version: str | None,
) -> bool:
    """True when ``match`` from NVD's ``cpeMatch`` list covers this asset.

    Product check: the cpeMatch criteria must share the same
    ``cpe:2.3:<part>:<vendor>:<product>`` prefix as the asset's CPE — we
    never confuse a Windows CVE with a Linux asset just because the CPE
    name happened to contain overlapping tokens.

    Version check (when ``asset_version`` is known):
        * ``versionStartIncluding`` / ``versionStartExcluding`` define the
          lower bound of the vulnerable range.
        * ``versionEndIncluding``   / ``versionEndExcluding``   the upper.
        * If *no* range fields are present the criteria itself carries the
          version: ``*`` or ``-`` → applies to every version,
          concrete token → must match ``asset_version`` exactly.

    When ``asset_version`` is None we don't have enough info to prune, so
    we accept any match for the correct product — callers that want strict
    behaviour should supply a version.
    """
    asset_prefix = _cpe_product_prefix(asset_cpe)
    match_prefix = _cpe_product_prefix(match.get("criteria", ""))
    if not asset_prefix or not match_prefix:
        return False
    # Accept when the NVD criteria product is a broader rollup of the
    # asset's product — e.g. asset=``microsoft:windows_10`` matched by a CVE
    # whose criteria targets ``microsoft:windows``. This covers the common
    # case where a vendor publishes an umbrella CVE against the OS family
    # rather than each build. Same-prefix (exact match) is the happy path.
    if asset_prefix != match_prefix and not asset_prefix.startswith(match_prefix + "_"):
        return False

    if not asset_version:
        return True

    lo_inc = match.get("versionStartIncluding")
    lo_exc = match.get("versionStartExcluding")
    hi_inc = match.get("versionEndIncluding")
    hi_exc = match.get("versionEndExcluding")

    if any((lo_inc, lo_exc, hi_inc, hi_exc)):
        if lo_inc and _compare_versions(asset_version, lo_inc) < 0:
            return False
        if lo_exc and _compare_versions(asset_version, lo_exc) <= 0:
            return False
        if hi_inc and _compare_versions(asset_version, hi_inc) > 0:
            return False
        if hi_exc and _compare_versions(asset_version, hi_exc) >= 0:
            return False
        return True

    # No range: fall back to the version slot in the criteria itself.
    criteria_parts = match.get("criteria", "").split(":")
    if len(criteria_parts) < 6:
        return True
    crit_version = criteria_parts[5]
    if crit_version in ("*", "-", ""):
        return True
    return _compare_versions(asset_version, crit_version) == 0


def _cve_applies_to_asset(
    cpe_matches: list[dict[str, Any]],
    asset_cpe: str,
    asset_version: str | None,
) -> bool:
    """True when at least one ``cpeMatch`` covers the asset."""
    if not cpe_matches:
        # No structured match data (rare but happens for very old CVEs).
        # Fall back to the old behaviour — link without version filtering.
        return True
    return any(
        _cpe_match_applies(m, asset_cpe, asset_version) for m in cpe_matches
    )


def _normalize_cpe_for_match(cpe_str: str) -> str:
    """Normalize a CPE for NVD ``virtualMatchString`` queries.

    NVD's ``cpeName`` parameter only matches exact CPE names, so an inferred
    CPE like ``cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*`` (version unknown)
    returns zero results — NVD stores CVEs against specific product CPEs
    such as ``windows_10_1607`` or ``windows_server_2019``.

    ``virtualMatchString`` does the opposite: it treats ``*`` / missing
    components as "match anything", so the generic CPE matches every
    concrete Windows CPE in the database.

    The API requires at least the first 5 segments (prefix + part + vendor +
    product + version); we trim trailing ``:*:*`` junk but keep the prefix
    intact.
    """
    parts = cpe_str.split(":")
    # Expected: ["cpe", "2.3", part, vendor, product, version, update, ...]
    if len(parts) < 6 or parts[0] != "cpe":
        return cpe_str
    # Keep everything up to and including the version field (index 5);
    # virtualMatchString accepts prefixes ending after any wildcard segment.
    prefix = ":".join(parts[:6])
    # Pad back up to the 13-segment canonical form (cpe:2.3:...) with wildcards
    # if needed — some NVD deployments reject shorter strings.
    while prefix.count(":") < 12:
        prefix += ":*"
    return prefix


def _nvd_date(dt: datetime) -> str:
    """Format a datetime for NVD's ISO-8601-with-millis requirement."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _build_date_windows(
    start: datetime,
    end: datetime,
    window_days: int = NVD_WINDOW_DAYS,
) -> list[tuple[datetime, datetime]]:
    """Split [start, end] into ≤120-day windows, newest first.

    Newest-first lets the caller stop early once MAX_CVES_PER_CPE is hit —
    the analyst sees recent CVEs rather than a random slice of old ones.
    """
    windows: list[tuple[datetime, datetime]] = []
    cursor_end = end
    while cursor_end > start:
        cursor_start = max(start, cursor_end - timedelta(days=window_days))
        windows.append((cursor_start, cursor_end))
        cursor_end = cursor_start - timedelta(seconds=1)
    return windows


def _cpe_to_keyword(cpe_str: str) -> str:
    """Extract a NVD-friendly keyword from a CPE 2.3 URI.

    NVD's ``virtualMatchString`` started returning 404 for prefix queries in
    mid-2025 (works only for fully-specified CPEs).  ``keywordSearch`` is the
    documented fallback that still works for vendor-only / version-wildcard
    CPEs and produces the same set of relevant CVEs (NVD does the matching
    server-side against CVE descriptions and configurations).

    Examples:
        cpe:2.3:o:microsoft:windows:*  → "microsoft windows"
        cpe:2.3:h:dahua:*              → "dahua"
        cpe:2.3:o:linux:linux_kernel:* → "linux linux_kernel"
    """
    parts = cpe_str.split(":")
    # parts: [cpe, 2.3, part, vendor, product, version, ...]
    vendor  = parts[3] if len(parts) > 3 and parts[3] not in ("", "*") else ""
    product = parts[4] if len(parts) > 4 and parts[4] not in ("", "*") else ""
    if vendor and product:
        return f"{vendor} {product}".replace("_", " ")
    if vendor:
        return vendor.replace("_", " ")
    if product:
        return product.replace("_", " ")
    return ""


async def _fetch_single_window(
    client: httpx.AsyncClient,
    cpe_str: str,
    normalized: str,
    window_start: datetime,
    window_end: datetime,
    results_per_page: int = 2000,
) -> list[dict[str, Any]]:
    """Fetch CVEs for one (CPE, 120-day window) pair with retry."""
    keyword = _cpe_to_keyword(cpe_str)
    if not keyword:
        return []
    params = {
        # keywordSearch instead of virtualMatchString — see _cpe_to_keyword docstring.
        "keywordSearch": keyword,
        "pubStartDate":  _nvd_date(window_start),
        "pubEndDate":    _nvd_date(window_end),
        "resultsPerPage": results_per_page,
    }

    last_exc: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = await client.get(NVD_API_BASE, params=params)

            if resp.status_code in _RETRY_STATUSES:
                wait = 2 ** attempt
                logger.warning(
                    "NVD retryable status",
                    extra={"status": resp.status_code, "cpe": cpe_str, "retry_in": wait},
                )
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(wait)
                    continue
                return []

            if resp.status_code != 200:
                logger.warning(
                    "NVD API error",
                    extra={
                        "status": resp.status_code,
                        "cpe": cpe_str,
                        "window": f"{window_start.date()}..{window_end.date()}",
                        "body": resp.text[:200],
                    },
                )
                return []

            data = resp.json()
            total = data.get("totalResults", 0)
            logger.info(
                "NVD window ok",
                extra={
                    "cpe": cpe_str,
                    "window": f"{window_start.date()}..{window_end.date()}",
                    "total": total,
                },
            )

            results: list[dict[str, Any]] = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                cvss_score, severity = _extract_cvss(cve)

                descriptions = cve.get("descriptions", [])
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc and descriptions:
                    desc = descriptions[0].get("value", "")

                # Flatten the cpeMatch tree into a list we can test
                # per-asset at link time without re-walking the nested
                # configurations → nodes → cpeMatch structure.
                cpe_matches: list[dict[str, Any]] = []
                for cfg in cve.get("configurations", []) or []:
                    for node in cfg.get("nodes", []) or []:
                        for m in node.get("cpeMatch", []) or []:
                            if not m.get("vulnerable", True):
                                continue
                            criteria = m.get("criteria")
                            if not criteria:
                                continue
                            cpe_matches.append({
                                "criteria": criteria,
                                "versionStartIncluding": m.get("versionStartIncluding"),
                                "versionStartExcluding": m.get("versionStartExcluding"),
                                "versionEndIncluding": m.get("versionEndIncluding"),
                                "versionEndExcluding": m.get("versionEndExcluding"),
                            })

                results.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": desc,
                    "published": cve.get("published", ""),
                    "cpe_matches": cpe_matches,
                })
            return results

        except httpx.TimeoutException:
            wait = 2 ** attempt
            logger.warning(
                "NVD timeout",
                extra={"cpe": cpe_str, "attempt": attempt, "retry_in": wait},
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(wait)
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "NVD request failed",
                extra={"cpe": cpe_str, "attempt": attempt, "error": str(exc)},
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(2 ** attempt)

    if last_exc is not None:
        logger.warning("NVD window exhausted retries", extra={"cpe": cpe_str, "error": str(last_exc)})
    return []


async def _fetch_cves_for_cpe(
    client: httpx.AsyncClient,
    cpe_str: str,
    *,
    horizon_start: datetime = CVE_HORIZON_START,
    max_cves: int = MAX_CVES_PER_CPE,
    delay_between_windows: float = DELAY_WITH_KEY,
    results_per_page: int | None = None,
) -> list[dict[str, Any]]:
    """Query NVD for CVEs matching a CPE, published since ``horizon_start``.

    Uses ``virtualMatchString`` so generic / version-less CPEs still match
    concrete product CPEs in NVD (e.g. ``cpe:2.3:o:microsoft:windows:*:...``
    matches every ``windows_10_*``, ``windows_server_*`` CVE).

    NVD caps date-filtered queries at 120-day windows, so we chunk from
    newest → oldest and stop once we have ``max_cves`` CVEs. This keeps the
    result set manageable (default 200) and biased toward recent issues.
    """
    if cpe_str in _cpe_cache:
        return _cpe_cache[cpe_str]

    normalized = _normalize_cpe_for_match(cpe_str)
    end = datetime.now(timezone.utc)
    # Default to fetching only what we need (max_cves + small buffer). This
    # keeps NVD's response payload small — a 30-CVE fetch is ~3× faster than
    # asking for 2000 when the underlying window has 400+ matches.
    effective_page_size = results_per_page if results_per_page is not None else min(max_cves + 10, 2000)

    all_results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for window_start, window_end in _build_date_windows(horizon_start, end):
        window_results = await _fetch_single_window(
            client, cpe_str, normalized, window_start, window_end,
            results_per_page=effective_page_size,
        )
        for r in window_results:
            if r["cve_id"] in seen_ids:
                continue
            seen_ids.add(r["cve_id"])
            all_results.append(r)

        if len(all_results) >= max_cves:
            logger.info(
                "NVD CVE cap reached",
                extra={"cpe": cpe_str, "count": len(all_results), "cap": max_cves},
            )
            break

        # Respect rate limits between windows.
        await asyncio.sleep(delay_between_windows)

    # Trim to cap (newest first is already the fetch order).
    all_results = all_results[:max_cves]

    if all_results:
        _cpe_cache[cpe_str] = all_results
    return all_results


def _extract_cvss(cve: dict) -> tuple[float, str]:
    """Extract the best CVSS score and severity from a CVE entry.

    Prefers CVSS v3.1, then v3.0, then v2.0.
    """
    metrics = cve.get("metrics", {})

    # Try CVSS 3.1
    for m in metrics.get("cvssMetricV31", []):
        data = m.get("cvssData", {})
        score = data.get("baseScore", 0.0)
        severity = data.get("baseSeverity", "UNKNOWN")
        return score, severity.lower()

    # Try CVSS 3.0
    for m in metrics.get("cvssMetricV30", []):
        data = m.get("cvssData", {})
        score = data.get("baseScore", 0.0)
        severity = data.get("baseSeverity", "UNKNOWN")
        return score, severity.lower()

    # Try CVSS 2.0
    for m in metrics.get("cvssMetricV2", []):
        data = m.get("cvssData", {})
        score = data.get("baseScore", 0.0)
        # CVSS v2 doesn't have baseSeverity, derive from score
        if score >= 7.0:
            severity = "high"
        elif score >= 4.0:
            severity = "medium"
        else:
            severity = "low"
        return score, severity

    return 0.0, "unknown"


async def _upsert_vulnerability(
    pool: asyncpg.Pool,
    cve_data: dict,
    cpe_str: str,
) -> str | None:
    """Upsert a vulnerability record and return its UUID."""
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO vulnerabilities (id, cve_id, cpe, cvss_score, severity, description)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (cve_id) DO UPDATE
                    SET cvss_score = EXCLUDED.cvss_score,
                        severity = EXCLUDED.severity,
                        description = EXCLUDED.description
                RETURNING id::text
            """,
                uuid.uuid4(),
                cve_data["cve_id"],
                cpe_str,
                cve_data["cvss_score"],
                cve_data["severity"],
                cve_data["description"],
            )
            return row["id"] if row else None
    except asyncpg.UniqueViolationError:
        # Race condition — another concurrent insert won; fetch existing
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id::text FROM vulnerabilities WHERE cve_id = $1",
                cve_data["cve_id"],
            )
            return row["id"] if row else None
    except Exception:
        logger.exception("Failed to upsert vulnerability", extra={"cve": cve_data["cve_id"]})
        return None


async def _link_asset_vulnerability(
    pool: asyncpg.Pool,
    asset_id: str,
    vuln_id: str,
) -> bool:
    """Link an asset to a vulnerability. Returns True if a new link was created."""
    try:
        async with pool.acquire() as conn:
            result = await conn.execute("""
                INSERT INTO asset_vulnerabilities (id, asset_id, vulnerability_id, detected_at)
                VALUES ($1, $2::uuid, $3::uuid, NOW())
                ON CONFLICT DO NOTHING
            """, uuid.uuid4(), uuid.UUID(asset_id), uuid.UUID(vuln_id))
            return "INSERT" in result
    except Exception:
        logger.exception(
            "Failed to link asset-vulnerability",
            extra={"asset_id": asset_id, "vuln_id": vuln_id},
        )
        return False
