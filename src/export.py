"""CSV export with provenance, ISO dates, and empty cells for missing values."""

import csv
from datetime import date
from pathlib import Path

from .constants import WORKLIST_CSV_COLUMNS
from . import config


def export_worklist_csv(worklist, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    info = worklist.catalog_info
    # Keep provenance on one physical line even with unusual supplied metadata.
    provenance = (
        f"# Catalog version: {info.get('catalog_version', 'Unknown')}; "
        f"Download date: {info.get('download_date') or 'Unknown'}; "
        f"Reference date: {worklist.reference_date}; Due soon: 0-{config.DUE_SOON_DAYS} days"
    ).replace("\r", " ").replace("\n", " ")
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(provenance + "\n")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(WORKLIST_CSV_COLUMNS)
        for record in worklist.get_records():
            # Keep the published CSV column names; read the canonical parser fields.
            values = [
                record.cve_id, record.vendor_project, record.product,
                record.date_added, record.due_date,
                record.due_status(worklist.reference_date) == "overdue",
                record.days_until_due(worklist.reference_date),
                record.age_in_days(worklist.reference_date),
                record.known_ransomware_campaign_use, record.required_action,
            ]
            writer.writerow([
                value.isoformat() if isinstance(value, date) else value
                for value in values
            ])
