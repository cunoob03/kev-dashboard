# KEV Prioritization Dashboard

A reproducible command-line dashboard for analyzing CISA's Known Exploited
Vulnerabilities (KEV) catalog. It reads a frozen local catalog snapshot and
creates a report, a prioritized remediation worklist, and four charts. The
project is defensive catalog analysis only: it does not scan systems, exploit
vulnerabilities, or contact remote services during normal use.

## Project at a glance

| Item | Value |
| --- | --- |
| Source | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Bundled snapshot | `data/known_exploited_vulnerabilities_2026-10-18.json` |
| Catalog version | `2026.10.16` |
| Download date | `2026-10-18` |
| Frozen reference date | `2026-10-18` |
| Records in snapshot | 1,748 |
| Supported Python | 3.11+ |

Snapshot integrity (SHA-256):

```text
b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d
```

The frozen input makes results reproducible for grading. Changing the reference
date recalculates date arithmetic; it does not download a newer catalog or
reconstruct historical catalog membership.

## Features

- Parses the local KEV JSON catalog into `VulnerabilityRecord` objects.
- Validates required fields, dates, malformed rows, and duplicate CVE IDs while
  retaining damaged source rows for transparent reporting.
- Calculates catalog age, days until due, and four deadline states.
- Filters by vendor, product, ransomware-use value, deadline state, and
  inclusive `date_added` range; filters combine with AND.
- Exports an overdue-first CSV worklist using documented, deterministic sorting.
- Produces vendor/product summaries, a text report, and four PNG charts.
- Includes automated tests and a repeatable 30-record date-calculation worksheet.

## Requirements and installation

Use Python 3.11 or later. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.dashboard
```

On Windows, activate with `.venv\Scripts\activate`. Charts use Matplotlib's
headless Agg backend. On hosts with a read-only home directory, configure
writable caches before running:

```bash
export MPLCONFIGDIR="$PWD/.cache/matplotlib"
export XDG_CACHE_HOME="$PWD/.cache"
```

## Run the dashboard

```bash
python -m src.dashboard
```

The command prints the report and creates these files in `outputs/`:

| Output | Purpose |
| --- | --- |
| `dashboard_report_2026-10-18.txt` | Provenance, filters, statistics, data quality, rankings, rules, and limitations |
| `prioritized_worklist_2026-10-18.csv` | Selected records in transparent remediation order |
| `plot_top_vendors.png` | Top vendors by catalog presence |
| `plot_due_status.png` | Overdue, due-soon, and not-yet-due counts |
| `plot_monthly_trend.png` | Catalog additions per month, including zero-count months |
| `plot_ransomware_by_vendor.png` | Known versus Unknown ransomware-use values for top vendors |

The CSV begins with a `#` provenance line. Skip that line when reading it with
`csv.DictReader` or importing it into a spreadsheet. Re-running into the same
directory replaces generated files; use `--output-dir` to retain a selection.

### Useful examples

```bash
# Exact, case-insensitive vendor or product filters
python -m src.dashboard --vendor Microsoft --output-dir outputs/microsoft
python -m src.dashboard --product Windows --output-dir outputs/windows

# Filters combine with AND
python -m src.dashboard --product Windows --ransomware Known \
  --due-status overdue --output-dir outputs/windows-overdue

# Inclusive date_added range
python -m src.dashboard --start-date 2026-01-01 --end-date 2026-10-18 \
  --output-dir outputs/recent

# Recalculate without changing the frozen input snapshot
python -m src.dashboard --reference-date 2026-10-20 --output-dir outputs/2026-10-20

# Select records without a usable catalog due date
python -m src.dashboard --due-status no_due_date --output-dir outputs/missing-dates
python -m src.dashboard --help
```

To analyze another local JSON file, pass `--catalog path/to/catalog.json`. Use
`--download-date YYYY-MM-DD` only when that provenance is known; otherwise the
report deliberately shows `Unknown` rather than guessing from file metadata.

## Prioritization policy

The worklist uses no invented severity, CVSS, or organization-specific risk
score. Its ordering is intentionally simple and auditable:

1. Overdue records first, with the most overdue deadline first.
2. Other records with a valid deadline next, earliest due date first.
3. Records without a usable due date last.
4. Ties use the oldest `date_added` first; fully tied records retain source order.

With the default configuration, **due soon** means from today through 14 days
ahead, inclusive. Due today is due soon, not overdue. Update
`DUE_SOON_DAYS` in `src/config.py` only when the team agrees to change this
project-wide policy. See [the full prioritization rules](docs/prioritization_rules.md).

## Data quality and interpretation

The dashboard checks data quality against the full catalog before filtering, so
a filter cannot hide malformed or duplicate source records. Missing or invalid
values become `None`, are retained in the report, and appear in explicit
missing-value buckets where appropriate.

- A vendor or product count measures catalog presence, not vendor security or
  an organization's exposure.
- `Unknown` ransomware use means unconfirmed—not confirmed absence.
- `Overdue` describes CISA's catalog deadline; it does not prove a particular
  organization has not remediated the issue.
- Monthly additions show catalog addition dates, not first-exploitation dates.
- The bundled catalog supplies no numeric severity score, so this project does
  not invent one.

## Test and verification workflow

```bash
python -m unittest discover -s tests -v
python -m src.sample_check
python -m src.verification
```

The automated suite covers parser validation, missing values, duplicate CVEs,
leap days, deadline boundaries, sorting stability, CSV quoting, empty outputs,
filtering, reference-date overrides, and the full frozen catalog. The sample
tools consistently select 30 distinct source rows using seed 42 and create:

- `outputs/verification_sample_2026-10-18.csv`
- `outputs/verification_math_2026-10-18.md`

The worksheet independently checks age, due offsets, overdue flags, and all
four deadline states. It supports—but does not replace—the required human
manual review of sampled source rows. See [validation notes](docs/validation.md).

## Project structure

```text
data/       Frozen CISA KEV catalog snapshot
docs/       Rules, validation notes, interface contract, and team handoffs
outputs/    Reproducible report, worklist, plots, and verification artifacts
src/        Parser, record model, filtering, prioritization, exports, and CLI
tests/      Unit and integration tests
```

The parser and dashboard share one record model and date policy:

```python
from src.parser import load_catalog
from src.dashboard import generate_dashboard

catalog_info, records = load_catalog()
report_path = generate_dashboard(records, catalog_info, vendor_filter="Microsoft")
```

For the integration contract, see [docs/interface_contract.md](docs/interface_contract.md).
For teammate ownership and maintenance notes, see:

- [Dashboard and prioritization handoff](docs/team_handoff_duy_dashboard_prioritization.txt)
- [Parser and date-logic handoff](docs/team_handoff_khoa_parser_date_logic.txt)

## Scope and safety boundary

This project is a defensive analysis tool for an authoritative public catalog.
It performs no exploit development, target scanning, or remote security testing.
