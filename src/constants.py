"""Output names and CSV columns; all runtime settings live in config.py."""
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
