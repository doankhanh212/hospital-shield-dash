"""Inference engine for the Passive Asset Intelligence Platform.

Classifies hospital network assets by device type, operating system, and vendor
using multi-signal analysis: MAC OUI, protocol/port behavior, DHCP vendor class,
HTTP User-Agent, and JA3 TLS fingerprints.

Usage::

    python -m passive_asset_intel infer
    python -m passive_asset_intel infer --dry-run
"""

from passive_asset_intel.inference.anomaly import detect_anomalies
from passive_asset_intel.inference.device_classifier import classify_asset
from passive_asset_intel.inference.engine import build_features, run_inference
from passive_asset_intel.inference.identity import find_and_merge_duplicates
from passive_asset_intel.inference.mac_vendor import MacVendorResolver
from passive_asset_intel.inference.writer import upsert_inference

__all__ = [
    "build_features",
    "classify_asset",
    "detect_anomalies",
    "find_and_merge_duplicates",
    "run_inference",
    "MacVendorResolver",
    "upsert_inference",
]
