"""Create a reproducible 30-record date-check worksheet for teammate review."""

import argparse
import csv
import random
from datetime import date
from pathlib import Path

from .catalog_adapter import load_catalog
from .constants import DEFAULT_CATALOG_PATH, DEFAULT_REFERENCE_DATE, PROJECT_ROOT
from .dashboard import iso_date


def export_verification_sample(records, output_dir, reference_date=DEFAULT_REFERENCE_DATE):
    """Select 10 source-order, 10 seeded random, and 10 overdue unique records.

    Expectations use date ordinals independently of the adapter's timedelta
    calculations. This automated comparison supports, but is not a claim of,
    a teammate's manual review.
    """
    unique = {}
    for record in records:
        unique.setdefault(record.cve_id, record)
    pool = list(unique.values())
    sample = pool[:10]
    seen = {record.cve_id for record in sample}
    remaining = [record for record in pool if record.cve_id not in seen]
    sample += random.Random(42).sample(remaining, min(10, len(remaining)))
    seen = {record.cve_id for record in sample}
    overdue = [
        record for record in pool
        if record.cve_id not in seen
        and record.due_date is not None and record.due_date < reference_date
    ]
    sample += overdue[:10]
    seen = {record.cve_id for record in sample}
    sample += [record for record in pool if record.cve_id not in seen][:30 - len(sample)]
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    csv_path = destination / f"verification_sample_{reference_date}.csv"
    columns = [
        "cve_id", "date_added", "due_date", "reference_date",
        "expected_age_days", "actual_age_days",
        "expected_days_until_due", "actual_days_until_due",
        "expected_is_overdue", "actual_is_overdue", "match?",
    ]
    calculations = [
        "# Date calculation examples", "",
        "Generated arithmetic examples for human review; manual review is still pending.", "",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for index, record in enumerate(sample):
            age = (
                reference_date.toordinal() - record.date_added.toordinal()
                if record.date_added is not None else None
            )
            days = (
                record.due_date.toordinal() - reference_date.toordinal()
                if record.due_date is not None else None
            )
            overdue = days is not None and days < 0
            matches = (age, days, overdue) == (
                record.age_days, record.days_until_due, record.is_overdue
            )
            writer.writerow(dict(zip(columns, [
                record.cve_id, record.date_added, record.due_date, reference_date,
                age, record.age_days, days, record.days_until_due,
                overdue, record.is_overdue, "yes" if matches else "no",
            ])))
            if index < 5:
                calculations += [
                    f"## {record.cve_id}", "",
                    f"- Age: {reference_date} − {record.date_added} = {age} days.",
                    f"- Days until due: {record.due_date} − {reference_date} = {days} days.",
                    f"- Overdue: {overdue} (days until due < 0).",
                    f"- Matches the record's computed values: {'yes' if matches else 'no'}.",
                    "",
                ]
    (destination / f"verification_math_{reference_date}.md").write_text(
        "\n".join(calculations), encoding="utf-8"
    )
    return csv_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--reference-date", type=iso_date, default=DEFAULT_REFERENCE_DATE)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "outputs")
    args = parser.parse_args(argv)
    try:
        records, _ = load_catalog(args.catalog, args.reference_date)
        path = export_verification_sample(records, args.output_dir, args.reference_date)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Verification worksheet saved to: {path}")


if __name__ == "__main__":
    main()
