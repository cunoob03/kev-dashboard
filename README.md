# KEV Prioritization Dashboard

Group project for Intro to Programming (VGU). Analyze the checked-in CISA
Known Exploited Vulnerabilities catalog and generate a text dashboard,
a prioritized CSV worklist, and four PNG charts.

The default run uses catalog **2026.10.16**, downloaded **2026-10-18**, with
**1,748 entries** and a frozen reference date of **2026-10-18**.
This is a command-line report generator; it does not require a web server.

## Install and run

Use Python 3.11 or later (validated with Python 3.12). From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.dashboard
```

On Windows, activate with `.venv\Scripts\activate` instead.
Charts use Matplotlib's headless Agg backend. If the cloud machine has a
read-only home directory, set writable caches before running:

```bash
export MPLCONFIGDIR="$PWD/.cache/matplotlib"
export XDG_CACHE_HOME="$PWD/.cache"
```

The report prints to the console and these files are created in `outputs/`:

| File | Contents |
| --- | --- |
| `dashboard_report_2026-10-18.txt` | Provenance, filters, statistics, quality issues, rankings, limitations |
| `prioritized_worklist_2026-10-18.csv` | Every selected entry in deadline priority order |
| `plot_top_vendors.png` | Top ten vendors; counts do not measure risk |
| `plot_due_status.png` | Overdue, due within 0–14 days, due after 14 days |
| `plot_monthly_trend.png` | Selected entries added per month, including zero-count months |
| `plot_ransomware_by_vendor.png` | Known versus Unknown ransomware use for top vendors |

Running again in the same output directory replaces the generated files.
Use a separate `--output-dir` for each selection you want to keep.
CSV files begin with a `#` provenance line; skip that first line when using
`csv.DictReader` or importing into a spreadsheet.

## Filter and change the reference date

Filters combine with AND. Vendor/product matches are exact and case-insensitive.
Date ranges apply to `date_added` and include both endpoints.

```bash
python -m src.dashboard --vendor Microsoft --output-dir outputs/microsoft
python -m src.dashboard --product Windows --ransomware Known --due-status overdue --output-dir outputs/windows
python -m src.dashboard --start-date 2026-01-01 --end-date 2026-10-18 --output-dir outputs/recent
python -m src.dashboard --reference-date 2026-10-20 --output-dir outputs/2026-10-20
python -m src.dashboard --due-status no_due_date --output-dir outputs/missing-dates
python -m src.dashboard --help
```

The parser and dashboard both use `VulnerabilityRecord` and the settings in
`src/config.py`. **Due soon means 0–14 days inclusive**, including today.
To change the project-wide window, edit `DUE_SOON_DAYS` in that one file.
The selected reference date is passed to every date method during filtering,
sorting, summary calculation, and export; input records are not modified.
Every chart, the CSV, and the summary use the same selected records.
The quality section always checks the **full input before filtering**, so
filters cannot hide problems. Empty selections still produce valid
reports, header-only CSVs, and charts explaining the empty result.

For another catalog, use `--catalog path/to/catalog.json`. Supply
`--download-date YYYY-MM-DD` only if known; otherwise its download date is
reported as `Unknown`. No download or credentials are required for the bundled
catalog.

Damaged record values become `None` and are reported; rows and duplicate CVE IDs
are retained. Counts include missing vendor/product values under explicit
display labels. The dashboard exits with status `0` for a clean run, `1` when
outputs were generated with quality issues, and `2` for invalid arguments or an
unreadable/invalid catalog structure. A failed load never becomes a successful
empty dashboard.

## Tests and verification handoff

```bash
python -m unittest discover -s tests -v
python -m src.sample_check
python -m src.verification
```

The tests cover the outline's ten fake records, deadline boundaries, stable
sorting, missing dates, leap days, non-mutation, CSV quoting, empty/filtered
output generation, reference-date changes, and the real catalog's date math.

Both verification commands select the same 30 distinct **source rows**, using
seed 42 from `config.py`. Duplicate CVE IDs are not removed. Smaller inputs use
all available rows. `sample_check` prints the sample to the console;
`verification` writes it
to `outputs/verification_sample_2026-10-18.csv`, along with five worked
arithmetic examples in `outputs/verification_math_2026-10-18.md`. Expected
values use date ordinals independently of the model's date subtraction.
The worksheet compares ages, due offsets, overdue flags, and all four statuses,
and includes source row numbers and catalog provenance.
These are automated checks and review aids; the validation teammate's manual
sign-off remains pending. See [validation notes](docs/validation.md).

## Team integration

The parser and dashboard are connected directly:

```python
from src.parser import load_catalog
from src.dashboard import generate_dashboard

catalog_info, records = load_catalog()
report_path = generate_dashboard(records, catalog_info, vendor_filter="Microsoft")
```

Use the existing checkout on a feature branch. `load_catalog()` returns
**metadata first, records second**. The model preserves all twelve catalog
fields, including `forensic_triage`. The former `catalog_adapter.py` and duplicate
quality checker have been removed. `constants.py` now contains only output
names and CSV column names; shared runtime settings live in `config.py`.

- [Interface contract](docs/interface_contract.md): required record attributes and metadata.
- [Prioritization rules](docs/prioritization_rules.md): ordering, missing data, and interpretation.
- `src/test_data.py`: the outline's ten fake records for independent development.
- `tests/test_parser.py`: eight fake JSON records plus malformed-input tests.
- `src/filters.py`, `src/prioritizer.py`, `src/counters.py`: selection and summaries.
- `src/plots.py`, `src/export.py`, `src/dashboard.py`: deliverable generation.

No severity scores are invented. A catalog deadline does not tell us whether
an organization has remediated a vulnerability. “Unknown” ransomware use means
unconfirmed, not absent.
