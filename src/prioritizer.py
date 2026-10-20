"""Transparent deadline ordering; no invented severity or risk scores."""

from datetime import date

import numpy as np

from .filters import filter_by_due_status


class PrioritizedWorklist:
    """A sorted copy of a record list, plus metadata and filter descriptions."""

    def __init__(self, records, catalog_info, applied_filters=None):
        self.catalog_info = dict(catalog_info)
        self.applied_filters = list(applied_filters or [])
        self.records = self._sort(records)

    def _sort(self, records):
        def priority(record):
            if record.due_date is None:
                group, deadline = 2, 0
            elif record.is_overdue:
                group, deadline = 0, record.days_until_due
            else:
                group, deadline = 1, record.due_date.toordinal()
            return (
                group, deadline,
                record.date_added is None,
                record.date_added or date.max,
            )
        # sorted() preserves input order for completely tied records.
        return sorted(records, key=priority)

    def summary_stats(self):
        ages = np.array([r.age_days for r in self.records if r.age_days is not None], dtype=float)
        days = np.array([
            r.days_until_due for r in self.records if r.days_until_due is not None
        ], dtype=float)
        return {
            "total": len(self),
            "overdue_count": len(filter_by_due_status(self.records, "overdue")),
            "due_soon_count": len(filter_by_due_status(self.records, "due_soon")),
            "not_yet_due_count": len(filter_by_due_status(self.records, "not_yet_due")),
            "no_due_date_count": sum(r.due_date is None for r in self.records),
            "mean_age_days": float(np.mean(ages)) if ages.size else None,
            "median_age_days": float(np.median(ages)) if ages.size else None,
            "mean_days_until_due": float(np.mean(days)) if days.size else None,
            "ransomware_known_count": sum(
                r.ransomware_use.casefold() == "known" for r in self.records
            ),
        }

    def get_records(self):
        """Return a new list so callers cannot reorder the stored worklist."""
        return list(self.records)

    def __len__(self):
        return len(self.records)
