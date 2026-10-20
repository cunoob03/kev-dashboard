# Integrated parser → dashboard contract

The project uses one parser, one record model, and one date policy. The dashboard
reads `VulnerabilityRecord` directly. The old `KEVRecord` adapter and its duplicate
JSON/date parsing have been removed.

## Decisions

- `src/config.py` is the source for the reference date, catalog path, download
  date, due-soon window, and verification sample settings.
- Default reference date: **2026-10-18**, never today's date automatically.
- Due soon: **0 through 14 days inclusive**. Change `DUE_SOON_DAYS` in config.py
  to change the project-wide policy; model, filters, charts, and reports use it.
- Preserve the parser's names and methods. Do not add fixed-reference-date
  property aliases: those can silently disagree with an overridden report date.
- `load_catalog(path)` returns **(metadata, records)**, in that order.
- Retain damaged rows and duplicates. Report source problems before filtering.
- Both verification tools select the same source rows using seed 42.

These are implementation decisions, not a claim of human review or sign-off.

## Record attributes

| Attribute | Type | Exact JSON source |
| --- | --- | --- |
| `cve_id` | `str` or `None` | `cveID` |
| `vendor_project` | `str` or `None` | `vendorProject` |
| `product` | `str` or `None` | `product` |
| `vulnerability_name` | `str` or `None` | `vulnerabilityName` |
| `date_added` | `datetime.date` or `None` | `dateAdded` |
| `due_date` | `datetime.date` or `None` | `dueDate` |
| `short_description` | `str` or `None` | `shortDescription` |
| `required_action` | `str` or `None` | `requiredAction` |
| `known_ransomware_campaign_use` | `str` or `None` | `knownRansomwareCampaignUse` |
| `forensic_triage` | `str` or `None` | `forensicTriage` |
| `notes` | `str` or `None` | `notes` |
| `cwes` | `list[str]` or `None` | `cwes` |

Missing/invalid values become `None`; an empty CWE list is valid. The parser
validates required text, CVE identifier format, date format/calendar validity,
and the types of optional fields. It retains the original meaningful text.
`validation_issues` is a separate diagnostic list, not a claimed CISA field.

The model methods all accept an optional `reference_date`:

```python
record.age_in_days(reference_date)     # reference_date - date_added, or None
record.days_until_due(reference_date) # due_date - reference_date, or None
record.due_status(reference_date)     # overdue / due_soon / not_yet_due / no_due_date
```

Days until due is negative for overdue records. Due today is due soon. Missing
addition dates do not prevent deadline calculations, and vice versa. Negative
ages are retained when the chosen date precedes addition to the catalog.

## Metadata and quality

The metadata dictionary contains `title`, `catalog_version`, `date_released`,
`record_count` (actual rows), `declared_record_count`, `file_name`, `download_date`,
`file_issues`, and `load_succeeded`.

The bundled file's download date is supplied by the project, not inferred from
its modification time or confused with its release date. Other files use `None`
unless a caller supplies documented provenance; the dashboard CLI accepts
`--download-date` for that purpose.

`load_succeeded=False` means reading the catalog structure failed. A parsed empty
list has `load_succeeded=True`, even though it has zero records. Success of the
load does not guarantee that all records are valid: inspect `file_issues` and
`find_data_quality_issues(records)` separately.

The quality dictionary includes missing required fields/dates, invalid-record
messages, duplicate IDs with source positions, `total_issues`, and
`affected_record_count`. Positions start at 1. An invalid date creates both an
unavailable-date flag and an invalid-value explanation; issue flags can overlap.
Duplicates count once per distinct duplicated ID, while all duplicate rows count
as affected records. Invalid/missing CVE IDs are not grouped as a duplicate ID.

Dashboard quality reporting covers the full original input before filtering.
Summary statistics, counts, charts, and worklist rows cover the selected records.
This preserves source positions and prevents filters from hiding input problems.

## Python integration

```python
from datetime import date
from src.parser import load_catalog
from src.dashboard import generate_dashboard

metadata, records = load_catalog()
report_path = generate_dashboard(
    records,
    metadata,
    reference_date=date(2026, 10, 20),
    vendor_filter="Microsoft",
    output_dir="outputs/microsoft-2026-10-20",
)
```

`generate_dashboard` returns the text report path and prints the report. It rejects
metadata indicating a failed load, but generates reports for recoverable data
issues. It does not mutate records or input metadata. `PrioritizedWorklist` also
accepts `reference_date`; its metadata is set to the actual calculation date.
Every date calculation uses model methods with that explicit date.

For the CLI, exit status 0 means a clean run; 1 means outputs exist but source
quality issues were detected; 2 means invalid arguments or a fatal load/output
error. No outputs are produced for a failed catalog load.

## CSV compatibility and empty selections

The published CSV column order remains unchanged. The column `vendor` reads
`vendor_project`; `ransomware_use` reads `known_ransomware_campaign_use`;
`age_days`, `days_until_due`, and `is_overdue` are calculated for the worklist's
reference date. These are export column names, not extra model attributes.

The first CSV line starts with `#` and gives version, download date, reference
date, and the due-soon policy. Skip it before using `csv.DictReader`. Dates are
ISO `YYYY-MM-DD`, missing values are empty cells, and booleans are True/False.

Empty selections generate a report, a header-only CSV, and four charts. Numeric
statistics without observations return `None`, displayed as `N/A`; counts remain
zero. Count summaries use NumPy population standard deviation (`ddof=0`).
