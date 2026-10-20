# Parser and dashboard validation handoff

## Reproduce

From the repository root after installing `requirements.txt`:

```bash
python -m unittest discover -s tests -v
python -m src.dashboard
python -m src.dashboard --vendor Microsoft --output-dir outputs/microsoft
python -m src.dashboard --reference-date 2026-10-20 --output-dir outputs/2026-10-20
python -m src.sample_check
python -m src.verification
```

On hosts with a read-only home directory, use the writable Matplotlib/font caches
shown in the README. The parser, console sample, and verification CSV generator
need only the Python standard library.

## Bundled snapshot expectations

Catalog version: `2026.10.16`. Default reference date: `2026-10-18`.

| Check | Expected |
| --- | ---: |
| Total records | 1,748 |
| Overdue | 1,745 |
| Due soon (0–14 days) | 3 |
| Not yet due (>14 days) | 0 |
| Missing due dates | 0 |
| Ransomware Known | 361 |
| File/header issues | 0 |
| Record-quality issue flags | 0 |
| Microsoft entries | 390 |

These expectations describe this frozen file, not future CISA catalogs.

## Automated coverage

Validated on 2026-10-20: **47 tests passed**. Full-catalog and Microsoft-filtered
runs generated all six dashboard outputs. A reference-date override to
2026-10-20 was checked against all 1,748 rows. At both reference dates, the console
and CSV selected the same thirty source rows and all worksheet comparisons
matched. All four regenerated charts were visually inspected. The frozen JSON
was compared byte-for-byte with the previously published catalog and is unchanged.

The suite tests the parser and dashboard together, rather than relying only on
separate passing suites. It covers:

- All twelve fields, including forensicTriage; date parsing and None handling.
- Deadline boundaries at -1, 0, 7, 8, 14, and 15 days; leap days and year boundaries.
- Shared threshold changes through the model, filter, summary, chart, report, and CSV.
- Direct parser-to-dashboard use and reference-date overrides throughout the output.
- Missing text/dates, malformed rows, duplicate IDs, and count mismatches.
- Full-source quality reporting even when filters exclude the damaged rows.
- Empty selections versus failed loads, and the corresponding CLI exit statuses.
- Sorting stability, non-mutation, CSV quoting, and valid headless PNG generation.
- Repeatable matching console/CSV samples and deliberate calculation mismatches.

`tests/test_parser.py` uses eight fake JSON rows. `src/test_data.py` keeps the
outline's ten examples as canonical VulnerabilityRecord objects. Their priority
order remains `001, 002, 009, 003, 004, 010, 005, 006, 008, 007`; their mean age is
45 days, median age 17 days, and mean due offset 10.125 days. The fixture has four
due-soon and three Known ransomware records; earlier outline examples saying
“exactly two” are inconsistent with those records.

## One thirty-row sample

Both verification commands use `src/sampling.py`, seed 42, and a sample size of 30
from config.py. Positions are distinct, source order is unchanged, and duplicate
CVE IDs remain eligible as separate source rows. Inputs with fewer rows use all
available rows. Reproducibility assumes the same input order and Python random
implementation.

`python -m src.verification` writes:

- `outputs/verification_sample_2026-10-18.csv`
- `outputs/verification_math_2026-10-18.md`

The worksheet includes source row, catalog version, download date, reference
date, expected/actual age, due offset, overdue flag, and due status. Expected date
values use calendar ordinals independently of the model's timedelta subtraction.
A test deliberately changes a calculation and confirms it is marked `no`.
Five worked examples provide arithmetic for review. An overridden reference date
selects the same rows and recalculates both expected and actual values.

## Human review remains pending

Parser/dashboard integration is implemented and automated checks are complete.
This does not constitute the validation teammate's manual sign-off. That teammate
should compare all thirty sampled rows against the original JSON, verify the
arithmetic and chart interpretations, and record their own review. No human
verification is claimed by the generated worksheet or this document.
