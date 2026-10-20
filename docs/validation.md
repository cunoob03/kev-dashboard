# Dashboard validation handoff

## Reproduce

From the repository root after installing `requirements.txt`:

```bash
python -m unittest discover -s tests -v
python -m src.dashboard
python -m src.dashboard --vendor Microsoft --output-dir outputs/microsoft
python -m src.verification
```

Use writable Matplotlib/font caches on a cloud host with a read-only home
directory, as described in the README.

## Expected bundled-catalog results

Catalog version: `2026.10.16`. Reference date: `2026-10-18`.

| Check | Expected |
| --- | ---: |
| Total records | 1,748 |
| Overdue | 1,745 |
| Due soon (0–7 days) | 3 |
| Not yet due (>7 days) | 0 |
| Missing due dates | 0 |
| Ransomware Known | 361 |
| Missing dates / duplicate ID issues | 0 |
| Microsoft entries | 390 |

These are snapshot checks, not permanent assertions about later CISA catalogs.
The real-data test currently targets this bundled file.

## Fake-data expectations

`src/test_data.py` preserves the outline's exact ten records. Their expected
order is `001, 002, 009, 003, 004, 010, 005, 006, 008, 007`.
The actual fixture has **4 due-soon** and **3 Known ransomware** records, as
specified in the outline's final expected-results table. Earlier build-step
examples that say “exactly 2” conflict with the fixture and are not used.

The fake-record mean age is 45 days, median age is 17 days, and mean days until
due is 10.125 days. Missing values are excluded independently.

## Thirty-entry worksheet

`python -m src.verification` writes:

- `outputs/verification_sample_2026-10-18.csv`
- `outputs/verification_math_2026-10-18.md`

Selection takes the first ten unique records, ten random remaining records
using seed 42, then ten remaining overdue records in source order. Smaller or
non-overdue catalogs are filled from remaining records up to thirty.

Expected values use calendar ordinals, while adapter values use timedelta
subtraction. The worksheet compares age, due offset, and overdue state. A
deliberately incorrect age is tested to ensure the comparison detects errors.
The markdown contains five arithmetic examples for review.

These outputs do **not** claim a human has performed manual verification.
The validation teammate should compare each sampled row with the original JSON,
check the date calculations, review the four charts, and record their sign-off.

## Team coordination still pending

- Parser teammate confirms `docs/interface_contract.md`.
- Integrate the teammate's parser through `generate_dashboard(records, metadata)`.
- Validation teammate manually verifies thirty entries and signs off.
- Group reviews the feature branch before merging into `main`.
