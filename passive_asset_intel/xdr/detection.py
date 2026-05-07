"""XDR hybrid detection rules — static threshold ⊕ baseline-aware multipliers.

Each rule fires only when activity exceeds *both* a static floor (so a fresh
asset still has guard-rails) AND a multiple of its own learned baseline (so
chatty assets don't trigger constantly).  Returns a list of alert dicts that
the pipeline then enriches and scores.
"""

from __future__ import annotations

from typing import Any

from passive_asset_intel.xdr.profile import (
    Baseline,
    is_common_domain,
    is_common_ja3,
)

# Static floors — must be exceeded even on a chatty asset.
STATIC = {
    "port_scan_min_ports":      20,
    "dns_spike_min_domains":    30,
    "data_exfil_min_bytes":     5 * 1024 * 1024,   # 5 MB
    "rare_domain_min_count":    5,                  # only fire if many rare domains
}

# Baseline multipliers — observed value must exceed baseline × N.
BASELINE_MULT = {
    "port_scan":         3.0,
    "dns_spike":         3.0,
    "data_exfiltration": 4.0,
}


def _safe_div(a: float, b: float) -> float:
    return a / b if b > 0 else 1.0


def detect(
    activity: dict[str, Any],
    baseline: Baseline,
    *,
    observed_domains: list[str] | None = None,
    observed_ja3:     list[str] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate all rules against *activity* + per-asset *baseline*.

    Args:
        activity:           Window snapshot from WindowAggregator.flush().
        baseline:           Baseline from compute_baseline() — may be cold.
        observed_domains:   Distinct domains seen in this window (for rare_domain).
        observed_ja3:       Distinct JA3 hashes seen in this window (for rare_ja3).

    Returns:
        List of partially-populated alert dicts:
            {asset, type, evidence, deviation}
        Severity and score are filled in later by the scoring layer.
    """
    asset = activity["asset_id"]
    alerts: list[dict[str, Any]] = []

    # ── Port scan ─────────────────────────────────────────────────────────
    port_floor = STATIC["port_scan_min_ports"]
    port_threshold = (
        max(port_floor, baseline.avg_unique_ports * BASELINE_MULT["port_scan"])
        if baseline.is_warm else port_floor
    )
    if activity["unique_ports"] > port_threshold:
        dev = _safe_div(activity["unique_ports"], baseline.avg_unique_ports or port_floor)
        alerts.append({
            "asset":     asset,
            "type":      "port_scan",
            "deviation": dev,
            "evidence": {
                "unique_ports":     activity["unique_ports"],
                "conn_count":       activity["conn_count"],
                "baseline_ports":   round(baseline.avg_unique_ports, 2),
                "threshold":        round(port_threshold, 2),
                "baseline_warm":    baseline.is_warm,
            },
        })

    # ── DNS spike ─────────────────────────────────────────────────────────
    dns_floor = STATIC["dns_spike_min_domains"]
    dns_threshold = (
        max(dns_floor, baseline.avg_unique_domains * BASELINE_MULT["dns_spike"])
        if baseline.is_warm else dns_floor
    )
    if activity["unique_domains"] > dns_threshold:
        dev = _safe_div(activity["unique_domains"], baseline.avg_unique_domains or dns_floor)
        alerts.append({
            "asset":     asset,
            "type":      "dns_spike",
            "deviation": dev,
            "evidence": {
                "unique_domains":   activity["unique_domains"],
                "dns_count":        activity["dns_count"],
                "baseline_domains": round(baseline.avg_unique_domains, 2),
                "threshold":        round(dns_threshold, 2),
                "baseline_warm":    baseline.is_warm,
            },
        })

    # ── Data exfiltration ─────────────────────────────────────────────────
    bytes_floor = STATIC["data_exfil_min_bytes"]
    bytes_threshold = (
        max(bytes_floor, baseline.avg_bytes_out * BASELINE_MULT["data_exfiltration"])
        if baseline.is_warm else bytes_floor
    )
    if activity["bytes_out"] > bytes_threshold:
        dev = _safe_div(activity["bytes_out"], baseline.avg_bytes_out or bytes_floor)
        alerts.append({
            "asset":     asset,
            "type":      "data_exfiltration",
            "deviation": dev,
            "evidence": {
                "bytes_out":         activity["bytes_out"],
                "bytes_out_mb":      round(activity["bytes_out"] / 1_048_576, 2),
                "baseline_bytes":    round(baseline.avg_bytes_out, 2),
                "baseline_bytes_mb": round(baseline.avg_bytes_out / 1_048_576, 2),
                "threshold":         round(bytes_threshold, 2),
                "baseline_warm":     baseline.is_warm,
            },
        })

    # ── Rare JA3 ───────────────────────────────────────────────────────────
    # Only meaningful once the baseline is warm — otherwise *every* JA3 is rare.
    if baseline.is_warm and observed_ja3:
        rare = [j for j in observed_ja3 if not is_common_ja3(baseline, j)]
        if rare:
            alerts.append({
                "asset":     asset,
                "type":      "rare_ja3",
                "deviation": 1.0,
                "evidence": {
                    "rare_ja3_count":  len(rare),
                    "rare_ja3_sample": rare[:5],
                    "baseline_warm":   True,
                },
            })

    # ── Rare domain ────────────────────────────────────────────────────────
    if baseline.is_warm and observed_domains:
        rare = [d for d in observed_domains if not is_common_domain(baseline, d)]
        if len(rare) >= STATIC["rare_domain_min_count"]:
            alerts.append({
                "asset":     asset,
                "type":      "rare_domain",
                "deviation": 1.0,
                "evidence": {
                    "rare_domain_count":  len(rare),
                    "rare_domain_sample": rare[:5],
                    "threshold":          STATIC["rare_domain_min_count"],
                    "baseline_warm":      True,
                },
            })

    return alerts
