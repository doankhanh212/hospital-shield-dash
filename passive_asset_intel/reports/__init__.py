"""Report generation package — CVSS-based HTML reports."""

from passive_asset_intel.reports.report_generator import (
    generate_html_report,
    severity_from_cvss,
)

__all__ = ["generate_html_report", "severity_from_cvss"]
