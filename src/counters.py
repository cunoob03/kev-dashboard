"""Dictionary tallies and NumPy summaries of catalog presence."""

import numpy as np


def _count(records, attribute):
    counts = {}
    for record in records:
        name = getattr(record, attribute)
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def count_by_vendor(records):
    """Count vendor entries, descending by count and alphabetically on ties."""
    return _count(records, "vendor")


def count_by_product(records):
    """Count product labels (identical labels across vendors are combined)."""
    return _count(records, "product")


def count_summary_stats(counts_dict):
    """Use population standard deviation; empty summaries contain None."""
    counts = np.array(list(counts_dict.values()), dtype=float)
    operations = {
        "max": np.max, "min": np.min, "mean": np.mean,
        "median": np.median, "std_dev": np.std,
    }
    return {
        name: float(operation(counts)) if counts.size else None
        for name, operation in operations.items()
    }


def find_data_quality_issues(records):
    """Count missing dates per record and duplicate IDs once per distinct ID."""
    missing_added = [r.cve_id for r in records if r.date_added is None]
    missing_due = [r.cve_id for r in records if r.due_date is None]
    ids = _count(records, "cve_id")
    duplicates = sorted(cve_id for cve_id, count in ids.items() if count > 1)
    return {
        "missing_date_added": missing_added,
        "missing_due_date": missing_due,
        "duplicate_cve_ids": duplicates,
        "total_issues": len(missing_added) + len(missing_due) + len(duplicates),
    }
