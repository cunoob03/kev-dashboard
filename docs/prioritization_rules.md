# KEV prioritization rules and limitations

The default reference date is **2026-10-18**, frozen for reproducible grading.
It can be overridden through `--reference-date` or the Python API.

## Ordering

1. Overdue records come first. A record is overdue only when
   `days_until_due < 0`. The most negative value comes first.
2. Other records with deadlines follow, earliest `due_date` first.
   Due today is not overdue.
3. Records without a due date go last.
4. Ties use `date_added`, oldest first. Missing `date_added` goes after known dates,
   including within the no-deadline group.
5. Complete ties preserve source order for repeatability.

Ransomware use is an available filter and summary, not an additional sort key.
No severity score is inferred or invented.

## Deadline groups and missing values

| Group | Days until due |
| --- | --- |
| Overdue | `< 0` |
| Due soon | `0` through `7`, inclusive |
| Not yet due | `> 7` |
| No due date | `None`; excluded from deadline filters and chart bars |

Missing ages/due offsets are excluded from their corresponding means and
medians. No observations produce `N/A`, not a fabricated zero. Data-quality
reports list missing dates and duplicate CVE IDs. Each missing-date occurrence
counts as one issue; each distinct duplicated CVE ID counts once. A record can
therefore contribute more than one issue.

## Interpretation

- KEV entries are known exploited vulnerabilities; the catalog does not provide
  a numeric severity score. NVD/CVSS enrichment is outside this dashboard's scope.
- Vendor counts describe catalog presence, not vendor security or an
  organization's exposure. Product counts combine identical product labels,
  including generic labels such as “Multiple Products”.
- “Unknown” ransomware use means CISA has not confirmed use. It does not mean
  ransomware use is absent. Other/missing ransomware values are excluded from
  the two chart bars and their excluded count is disclosed.
- “Overdue” describes a catalog deadline relative to the selected date. The
  catalog provides no organization-specific asset inventory or remediation
  status, so this is not proof that a system remains unpatched.
- Catalog addition dates are not dates of first exploitation. Monthly charts
  include zero-count months between the first and last observed month.
- Reference-date overrides recalculate arithmetic, but do not download a newer
  catalog or reconstruct historical membership.
- Filters combine with AND. All generated outputs describe the same selection;
  the report also identifies the full source catalog count.
- This program analyzes the supplied catalog. It does not scan or exploit systems.
