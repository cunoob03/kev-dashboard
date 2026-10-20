# Parser → dashboard interface

This is the proposed implementation contract for teammate review. It has not
yet been confirmed by the parser teammate. The parser supplies
`(list[KEVRecord], catalog_info)`; records may be dataclasses or ordinary objects.
The dashboard reads attributes, not dictionary keys, and does not mutate input
records, their CWE lists, the input list, or metadata.

## Record attributes

| Attribute | Type | JSON source or calculation |
| --- | --- | --- |
| `cve_id` | `str` | `cveID` |
| `vendor` | `str` | `vendorProject` |
| `product` | `str` | `product` |
| `vuln_name` | `str` | `vulnerabilityName` |
| `date_added` | `datetime.date \| None` | Parsed `dateAdded` |
| `due_date` | `datetime.date \| None` | Parsed `dueDate` |
| `short_description` | `str` | `shortDescription` |
| `required_action` | `str` | `requiredAction` |
| `ransomware_use` | `str` | `knownRansomwareCampaignUse` |
| `notes` | `str` | `notes` |
| `cwes` | `list[str]` | `cwes` |
| `age_days` | `int \| None` | `(reference_date - date_added).days` |
| `days_until_due` | `int \| None` | `(due_date - reference_date).days` |
| `is_overdue` | `bool` | `days_until_due is not None and days_until_due < 0` |

All attributes must exist. Missing dates become `None`; their corresponding
derived integers are `None`. Missing due dates imply `is_overdue=False`.
Dates are calendar dates, not datetimes. Negative ages are retained if a caller
chooses a reference date before a record's addition; changing the reference date
does not reconstruct an earlier catalog snapshot.

Direct calls to filters and `PrioritizedWorklist` assume these computed fields
are mutually consistent and use the same reference date. `generate_dashboard`
copies and recalculates all date-derived fields itself. With no override, it
always uses `2026-10-18`, rather than the system clock or metadata date.

## Metadata

```python
catalog_info = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalog_version": "2026.10.16",
    "date_released": "2026-10-16T17:15:48.8752Z",
    "total_count": 1748,
    "download_date": "2026-10-18",
    "reference_date": "2026-10-18",
}
```

`total_count` describes the complete source catalog; selected counts are computed
separately. Unknown provenance should be explicitly reported as `"Unknown"`.
The dashboard copies metadata and sets `reference_date` to the actual calculation
date. Chart metadata additionally includes the applied filter descriptions.

## Entry points

```python
from datetime import date
from src.dashboard import generate_dashboard
from src.prioritizer import PrioritizedWorklist

# Use the parser teammate's objects directly.
report_path = generate_dashboard(
    records,
    catalog_info,
    reference_date=date(2026, 10, 18),
    vendor_filter="Microsoft",
    output_dir="outputs/microsoft",
)

# For already-normalized records:
worklist = PrioritizedWorklist(records, catalog_info)
stats = worklist.summary_stats()
```

`generate_dashboard` supports the outline's parameters plus an optional
`output_dir`. It returns the text report's path as a string and prints the report.
It generates all four charts and a prioritized CSV from the filtered selection.
This follows the outline's integration requirement that charts reflect filters;
the monthly-plot docstring's conflicting “all records, not filtered” note is not
used. Call `plot_monthly_trend` with the full list separately if a full-catalog
comparison is needed.

The standalone `load_catalog` adapter handles JSON input for the CLI. It rejects
invalid nonempty dates and count mismatches with explicit errors. Missing/empty
dates are allowed and reported as data-quality issues. Duplicate IDs are retained
and flagged, never silently deduplicated in dashboard totals.

## Empty input and exports

- Statistics with no numeric observations return `None`, displayed as `N/A`.
- Counts and date-status totals remain zero.
- `count_summary_stats` uses NumPy population standard deviation (`ddof=0`).
- CSV dates are ISO `YYYY-MM-DD`; missing values are empty cells.
- CSV booleans are `True`/`False`; the first line is provenance, the second is
  the column header. Use Python's CSV reader to handle quoted commas/newlines.
- Record references are read-only by convention. `get_records()` returns a new
  list; it does not deep-copy every contained object.
