"""Print catalog metadata and a reproducible random sample for manual review.

Run from the repository root:
    python -m src.sample_check
    python -m src.sample_check --reference-date 2026-10-20

This script reads local JSON only and writes nothing to the frozen catalog.
It uses only Python's standard library. No network calls are made.
"""

import argparse

from . import config
from .parser import find_data_quality_issues, load_catalog, parse_date
from .sampling import sample_positions


def print_sample(path=config.CATALOG_PATH, reference_date=config.DEFAULT_REFERENCE_DATE):
    """Print metadata, issue details, and up to 30 records; return issue count.

    Seed 42 gives the same selections for the same input order and Python
    random implementation. Sample positions are distinct; duplicate CVE IDs
    remain eligible because they represent separate rows in the source.
    """
    metadata, records = load_catalog(path)
    issues = find_data_quality_issues(records)

    print("CATALOG METADATA")
    for name, value in metadata.items():
        print(f"{name}: {value}")
    print(f"reference_date: {reference_date}")
    print(f"due_soon_days: {config.DUE_SOON_DAYS}")
    print(f"Total records: {len(records)}")
    print(f"File/header issues: {len(metadata['file_issues'])}")
    print(f"Record issue flags: {issues['total_issues']}")
    print(f"Affected records: {issues['affected_record_count']}")
    total_issues = len(metadata["file_issues"]) + issues["total_issues"]
    print(f"Total data-quality issue flags: {total_issues}")

    # Print the details as well as the count so the reviewer can locate problems.
    if issues["total_issues"] > 0:
        print("\nRECORD ISSUE DETAILS")
        for name, values in issues.items():
            if name not in ("total_issues", "affected_record_count") and values:
                print(f"{name}: {values}")

    # Select positions so the printed source row number can locate each record.
    positions = sample_positions(records)

    print(f"\nRANDOM SAMPLE: {len(positions)} records (seed {config.VERIFICATION_SEED})")
    for sample_number, position in enumerate(positions, start=1):
        record = records[position]
        print(f"\n{sample_number}. {record.cve_id} (source record {position + 1})")
        print(f"   Vendor/project: {record.vendor_project}")
        print(f"   Product: {record.product}")
        print(f"   Date added: {record.date_added}")
        print(f"   Due date: {record.due_date}")
        print(f"   Age in days: {record.age_in_days(reference_date)}")
        print(f"   Days until due: {record.days_until_due(reference_date)}")
        print(f"   Status: {record.due_status(reference_date)}")

    return total_issues


def main(argv=None):
    """Read command-line options; use a nonzero exit status for detected issues."""
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument(
        "--catalog",
        default=config.CATALOG_PATH,
        help="Local catalog file; defaults to the frozen project catalog.",
    )
    command.add_argument(
        "--reference-date",
        default=config.DEFAULT_REFERENCE_DATE.isoformat(),
        help="Calculation date in YYYY-MM-DD format; defaults to the frozen date.",
    )
    arguments = command.parse_args(argv)
    reference_date = parse_date(arguments.reference_date)
    if reference_date is None:
        command.error("--reference-date must be a valid date in YYYY-MM-DD format")

    issue_count = print_sample(arguments.catalog, reference_date)
    if issue_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
