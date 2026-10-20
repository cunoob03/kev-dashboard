"""Dictionary tallies and NumPy summaries of catalog presence."""

import numpy as np


def _count(records, attribute, missing_label):
    counts = {}
    for record in records:
        name = getattr(record, attribute)
        if name is None:
            name = missing_label
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def count_by_vendor(records):
    """Count vendor entries, descending by count and alphabetically on ties."""
    return _count(records, "vendor_project", "(missing vendor)")


def count_by_product(records):
    """Count product labels (identical labels across vendors are combined)."""
    return _count(records, "product", "(missing product)")


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
