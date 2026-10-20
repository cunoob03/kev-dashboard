"""Transparent deadline ordering; no invented severity or risk scores."""

from datetime import date

import numpy as np

from .filters import filter_by_due_status
from . import config


class PrioritizedWorklist:
    """A sorted copy of a record list, plus metadata and filter descriptions."""

    def __init__(self, records, catalog_info, applied_filters=None,
                 reference_date=config.DEFAULT_REFERENCE_DATE):
        if type(reference_date) is not date:
            raise ValueError("reference_date must be a datetime.date")
        self.reference_date = reference_date
        self.catalog_info = dict(catalog_info)
        self.catalog_info["reference_date"] = reference_date.isoformat()
        self.applied_filters = list(applied_filters or [])
        self.records = self._sort(records)

    def _sort(self, records):
        def priority(record):
            if record.due_date is None:
                group, deadline = 2, 0
            elif record.due_status(self.reference_date) == "overdue":
                group, deadline = 0, record.days_until_due(self.reference_date)
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
        ages = np.array([
            r.age_in_days(self.reference_date) for r in self.records if r.date_added is not None
        ], dtype=float)
        days = np.array([
            r.days_until_due(self.reference_date) for r in self.records if r.due_date is not None
        ], dtype=float)
        return {
            "total": len(self),
            "overdue_count": len(filter_by_due_status(self.records, "overdue", self.reference_date)),
            "due_soon_count": len(filter_by_due_status(self.records, "due_soon", self.reference_date)),
            "not_yet_due_count": len(filter_by_due_status(self.records, "not_yet_due", self.reference_date)),
            "no_due_date_count": sum(r.due_date is None for r in self.records),
            "mean_age_days": float(np.mean(ages)) if ages.size else None,
            "median_age_days": float(np.median(ages)) if ages.size else None,
            "mean_days_until_due": float(np.mean(days)) if days.size else None,
            "ransomware_known_count": sum(
                (r.known_ransomware_campaign_use or "").casefold() == "known"
                for r in self.records
            ),
        }

    def get_records(self):
        """Return a new list so callers cannot reorder the stored worklist."""
        return list(self.records)

    def __len__(self):
        return len(self.records)
