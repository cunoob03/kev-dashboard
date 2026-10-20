"""CSV export with provenance, ISO dates, and empty cells for missing values."""

import csv
from datetime import date
from pathlib import Path

from .constants import WORKLIST_CSV_COLUMNS


def export_worklist_csv(worklist, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    info = worklist.catalog_info
    # Keep provenance on one physical line even with unusual supplied metadata.
    provenance = (
        f"# Catalog version: {info.get('catalog_version', 'Unknown')}; "
        f"Reference date: {info.get('reference_date', 'Unknown')}"
    ).replace("\r", " ").replace("\n", " ")
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(provenance + "\n")
        writer = csv.writer(stream)
        writer.writerow(WORKLIST_CSV_COLUMNS)
        for record in worklist.get_records():
            values = [getattr(record, column) for column in WORKLIST_CSV_COLUMNS]
            writer.writerow([
                value.isoformat() if isinstance(value, date) else value
                for value in values
            ])
