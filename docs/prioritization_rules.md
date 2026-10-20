# KEV prioritization rules and limitations

The default reference date is **2026-10-18**, frozen for reproducible grading.
It can be overridden through `--reference-date` or the Python API. Shared
settings live in `src/config.py`; due soon uses `DUE_SOON_DAYS = 14`.

## Ordering

1. Overdue records first: negative `days_until_due(reference_date)`, most negative first.
2. Other records with deadlines follow, earliest due date first. Due today is not overdue.
3. Records without a usable due date go last.
4. Ties use the oldest `date_added` first; missing addition dates sort after known dates.
5. Complete ties retain source order, including duplicate records.

Ransomware use is a filter and summary, not an extra priority key. No severity
score or organization-specific risk score is inferred or invented.

## Deadline groups

| Group | Days until due |
| --- | --- |
| Overdue | `< 0` |
| Due soon | `0` through `14`, inclusive |
| Not yet due | `> 14` |
| No due date | `None` |

Filters, worklist statistics, and CSV calculations call the model methods using
the chosen reference date. Chart labels and report text use the shared threshold.
`no_due_date` is available as a filter; the deadline chart discloses its count
separately from its three dated bars.

## Data quality

Missing/invalid required fields and duplicate IDs are reported by the parser.
Damaged rows remain in the worklist unless excluded by an explicit filter.
Absent vendor/product labels form explicit `(missing vendor)` / `(missing product)`
buckets without changing the underlying None values. Date-dependent filters
exclude records lacking the relevant date, except the explicit no-due-date filter.

The report shows quality findings for the full input before selection. It includes
source row numbers, file/header problems, individual issue flags, and distinct
affected-record counts. A single invalid date can have two flags (unavailable
value and invalid-value explanation). Invalid JSON or a missing record list is a
failed load and cannot be presented as a clean empty dashboard.

Missing ages/due offsets are excluded from their corresponding statistics.
No observations produce `N/A`, not a fabricated zero.

## Interpretation

- KEV identifies known exploited vulnerabilities but supplies no numeric severity
  score. CVSS/NVD enrichment is outside this project.
- Vendor counts describe catalog presence, not vendor security or an organization's
  exposure. Product counts combine identical labels across vendors.
- Ransomware “Unknown” means unconfirmed use, not confirmed absence. Other/missing
  values are excluded from the two ransomware bars and the excluded count is shown.
- “Overdue” describes a catalog deadline, not proof that an organization remains
  unpatched. The catalog provides no organization-specific remediation status.
- Monthly additions use `date_added`, not the date of first exploitation. Zero-count
  months between the first and last observed month are included.
- Reference-date changes recalculate arithmetic; they do not download a newer
  catalog or reconstruct historical catalog membership.
- Filters combine with AND. All charts, counts, and exported worklist rows use
  the same selection; provenance and quality findings describe the full source.
- The program reads local JSON only. It does not call remote APIs, scan, or exploit systems.
