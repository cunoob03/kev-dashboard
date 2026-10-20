"""Shared defaults for reproducible catalog reports."""

from datetime import date
from pathlib import Path

DEFAULT_REFERENCE_DATE = date(2026, 10, 18)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT / "data" / "known_exploited_vulnerabilities_2026-10-18.json"
)
WORKLIST_CSV_COLUMNS = [
    "cve_id", "vendor", "product", "date_added", "due_date", "is_overdue",
    "days_until_due", "age_days", "ransomware_use", "required_action",
]
PLOT_FILENAMES = [
    "plot_top_vendors.png",
    "plot_due_status.png",
    "plot_monthly_trend.png",
    "plot_ransomware_by_vendor.png",
]
