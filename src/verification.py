"""Create a reproducible 30-record date-check worksheet for teammate review."""

import argparse
import csv
import json
from pathlib import Path

from . import config
from .parser import load_catalog, parse_date, find_data_quality_issues
from .sampling import sample_positions


def export_verification_sample(records, output_dir,
                               reference_date=config.DEFAULT_REFERENCE_DATE,
                               catalog_info=None):
    """Use the same random source rows as sample_check, without deduplicating.

    Expectations use date ordinals independently of the model's timedelta
    calculations. This automated comparison supports, but is not a claim of,
    a teammate's manual review.
    """
    info = catalog_info or {}
    positions = sample_positions(records)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    csv_path = destination / f"verification_sample_{reference_date}.csv"
    columns = [
        "source_record", "catalog_version", "download_date",
        "cve_id", "date_added", "due_date", "reference_date",
        "expected_age_days", "actual_age_days",
        "expected_days_until_due", "actual_days_until_due",
        "expected_is_overdue", "actual_is_overdue",
        "expected_status", "actual_status", "match?",
    ]
    calculations = [
        "# Date calculation examples", "",
        "Generated arithmetic examples for human review; manual review is still pending.", "",
        f"Catalog version: {info.get('catalog_version', 'Unknown')}",
        f"Download date: {info.get('download_date') or 'Unknown'}",
        f"Reference date: {reference_date}; due-soon limit: {config.DUE_SOON_DAYS} days.",
        f"Sample seed: {config.VERIFICATION_SEED}. Source record numbers start at 1.", "",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for index, position in enumerate(positions):
            record = records[position]
            age = (
                reference_date.toordinal() - record.date_added.toordinal()
                if record.date_added is not None else None
            )
            days = (
                record.due_date.toordinal() - reference_date.toordinal()
                if record.due_date is not None else None
            )
            overdue = days is not None and days < 0
            if days is None:
                expected_status = "no_due_date"
            elif days < 0:
                expected_status = "overdue"
            elif days <= config.DUE_SOON_DAYS:
                expected_status = "due_soon"
            else:
                expected_status = "not_yet_due"
            actual_age = record.age_in_days(reference_date)
            actual_days = record.days_until_due(reference_date)
            actual_status = record.due_status(reference_date)
            actual_overdue = actual_status == "overdue"
            matches = (age, days, overdue, expected_status) == (
                actual_age, actual_days, actual_overdue, actual_status)
            writer.writerow(dict(zip(columns, [
                position + 1, info.get("catalog_version", "Unknown"),
                info.get("download_date") or "Unknown",
                record.cve_id, record.date_added, record.due_date, reference_date,
                age, actual_age, days, actual_days,
                overdue, actual_overdue, expected_status, actual_status,
                "yes" if matches else "no",
            ])))
            if index < 5:
                calculations += [
                    f"## {record.cve_id} (source record {position + 1})", "",
                    f"- Age: {reference_date} − {record.date_added} = {age} days."
                    if age is not None else "- Age: unavailable because date_added is missing.",
                    f"- Days until due: {record.due_date} − {reference_date} = {days} days."
                    if days is not None else "- Days until due: unavailable because due_date is missing.",
                    f"- Overdue: {overdue} (days until due < 0).",
                    f"- Due status: {expected_status}.",
                    f"- Matches the record's computed values: {'yes' if matches else 'no'}.",
                    "",
                ]
    (destination / f"verification_math_{reference_date}.md").write_text(
        "\n".join(calculations), encoding="utf-8"
    )
    return csv_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=config.CATALOG_PATH)
    parser.add_argument("--reference-date", default=config.DEFAULT_REFERENCE_DATE.isoformat())
    parser.add_argument("--output-dir", type=Path, default=config.PROJECT_ROOT / "outputs")
    args = parser.parse_args(argv)
    reference = parse_date(args.reference_date)
    if reference is None:
        parser.error("--reference-date must be a valid date in YYYY-MM-DD format")
    try:
        info, records = load_catalog(args.catalog)
        if not info["load_succeeded"]:
            parser.error("; ".join(info["file_issues"]))
        path = export_verification_sample(records, args.output_dir, reference, info)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Verification worksheet saved to: {path}")
    issues = find_data_quality_issues(records)
    with path.open(newline="", encoding="utf-8") as stream:
        mismatches = sum(row["match?"] != "yes" for row in csv.DictReader(stream))
    print(f"File/header issues: {info['file_issues']}")
    print(f"Record issue flags: {issues['total_issues']}; sample mismatches: {mismatches}")
    if issues["total_issues"]:
        print(json.dumps(issues, indent=2))
    return int(bool(info["file_issues"] or issues["total_issues"] or mismatches))


if __name__ == "__main__":
    raise SystemExit(main())
