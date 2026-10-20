"""Generate a text report, prioritized CSV, and four PNG charts."""

import argparse
from datetime import date
from pathlib import Path

from .catalog_adapter import load_catalog, records_at_reference_date
from .constants import DEFAULT_CATALOG_PATH, DEFAULT_REFERENCE_DATE, PLOT_FILENAMES, PROJECT_ROOT
from .counters import (
    count_by_product, count_by_vendor, count_summary_stats, find_data_quality_issues,
)
from .export import export_worklist_csv
from .filters import (
    filter_by_date_range, filter_by_due_status, filter_by_product,
    filter_by_ransomware, filter_by_vendor,
)
from .plots import (
    plot_due_status, plot_monthly_trend, plot_ransomware_by_vendor, plot_top_vendors,
)
from .prioritizer import PrioritizedWorklist


def _number(value):
    if value is None:
        return "N/A"
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def build_report_text(worklist, vendor_counts, product_counts,
                      catalog_info, applied_filters, data_quality_issues):
    """Build a report of the selected records and their catalog provenance."""
    lines = [
        "KEV DASHBOARD / PRIORITIZATION",
        str(catalog_info.get("title", "KEV catalog")),
        f"Catalog version: {catalog_info.get('catalog_version', 'Unknown')}",
        f"Released: {catalog_info.get('date_released', 'Unknown')}",
        f"Download date: {catalog_info.get('download_date', 'Unknown')}",
        f"Reference date: {catalog_info.get('reference_date', 'Unknown')}",
        f"Full catalog entries: {catalog_info.get('total_count', 'Unknown')}",
        "Applied filters: " + ("; ".join(applied_filters) if applied_filters else "None"),
        "",
        "SUMMARY — SELECTED RECORDS",
    ]
    lines.extend(f"{key}: {_number(value)}" for key, value in worklist.summary_stats().items())
    lines += ["", "DATA QUALITY — SELECTED RECORDS"]
    for key, value in data_quality_issues.items():
        lines.append(f"{key}: {', '.join(value) or 'None'}" if isinstance(value, list)
                     else f"{key}: {value}")
    for title, counts in [("VENDORS", vendor_counts), ("PRODUCTS", product_counts)]:
        lines += ["", f"TOP 10 {title} — COUNTS ≠ RISK"]
        lines.extend(f"{name}: {count}" for name, count in list(counts.items())[:10])
        if not counts:
            lines.append("No matching records.")
        lines.append("Count statistics (population standard deviation):")
        lines.extend(
            f"  {key}: {_number(value)}" for key, value in count_summary_stats(counts).items()
        )
    lines += [
        "",
        "PRIORITIZATION",
        "Overdue first (most overdue first); then earliest future deadline.",
        "Missing due dates last. Ties: oldest date_added first, missing dates last.",
        "Completely tied records keep their input order. No severity scores are invented.",
        "",
        "INTERPRETATION",
        "Counts reflect catalog presence, not vendor security or organizational risk.",
        "Overdue describes a catalog deadline, not proof that an organization is unpatched.",
        "Ransomware Unknown means unconfirmed use, not confirmed absence.",
        "Missing dates are excluded from the corresponding date statistics.",
        "Product counts combine identical product labels across vendors.",
        "All charts and the CSV use the same selected records as this report.",
        "",
        "OUTPUTS — alongside this report",
        f"prioritized_worklist_{catalog_info['reference_date']}.csv",
        *PLOT_FILENAMES,
        "",
    ]
    return "\n".join(lines)


def generate_dashboard(records, catalog_info, reference_date=None,
                       vendor_filter=None, product_filter=None,
                       ransomware_filter=None, due_status_filter=None,
                       start_date=None, end_date=None, output_dir=None):
    """Generate all six outputs, print the report, and return its path.

    reference_date defaults to the frozen project date. Dates are recalculated
    on copies before filtering. output_dir is optional for isolated runs.
    """
    reference = reference_date if reference_date is not None else DEFAULT_REFERENCE_DATE
    selected = records_at_reference_date(records, reference)
    info = dict(catalog_info)
    info["reference_date"] = reference.isoformat()
    applied = []
    for label, value, function in [
        ("vendor", vendor_filter, filter_by_vendor),
        ("product", product_filter, filter_by_product),
        ("ransomware", ransomware_filter, filter_by_ransomware),
        ("due status", due_status_filter, filter_by_due_status),
    ]:
        if value is not None:
            selected = function(selected, value)
            applied.append(f"{label} = {value}")
    if start_date is not None or end_date is not None:
        selected = filter_by_date_range(selected, start_date, end_date)
        applied.append(f"date_added = {start_date or 'any'} to {end_date or 'any'} (inclusive)")
    info["applied_filters"] = applied
    worklist = PrioritizedWorklist(selected, info, applied)
    vendors, products = count_by_vendor(selected), count_by_product(selected)
    issues = find_data_quality_issues(selected)
    destination = Path(output_dir) if output_dir is not None else PROJECT_ROOT / "outputs"
    destination.mkdir(parents=True, exist_ok=True)
    plot_top_vendors(vendors, info, destination / PLOT_FILENAMES[0])
    plot_due_status(worklist, info, destination / PLOT_FILENAMES[1])
    plot_monthly_trend(selected, info, destination / PLOT_FILENAMES[2])
    plot_ransomware_by_vendor(selected, info, destination / PLOT_FILENAMES[3])
    export_worklist_csv(worklist, destination / f"prioritized_worklist_{reference}.csv")
    report = build_report_text(worklist, vendors, products, info, applied, issues)
    report_path = destination / f"dashboard_report_{reference}.txt"
    report_path.write_text(report, encoding="utf-8")
    print(report)
    return str(report_path)


def iso_date(value):
    """Strict CLI date parser with a short, actionable error."""
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError
        return parsed
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a valid date in YYYY-MM-DD format") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--reference-date", type=iso_date, default=DEFAULT_REFERENCE_DATE)
    parser.add_argument("--download-date", type=iso_date, help="Known catalog download date")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "outputs")
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--ransomware", type=str.title, choices=["Known", "Unknown"])
    parser.add_argument("--due-status", choices=["overdue", "due_soon", "not_yet_due"])
    parser.add_argument("--start-date", type=iso_date)
    parser.add_argument("--end-date", type=iso_date)
    args = parser.parse_args(argv)
    if args.start_date and args.end_date and args.start_date > args.end_date:
        parser.error("--start-date must not be after --end-date")
    download_date = args.download_date
    if download_date is None and args.catalog.resolve() == DEFAULT_CATALOG_PATH.resolve():
        download_date = date(2026, 10, 18)
    try:
        records, info = load_catalog(args.catalog, args.reference_date, download_date)
        path = generate_dashboard(
            records, info, args.reference_date, args.vendor, args.product,
            args.ransomware, args.due_status, args.start_date, args.end_date,
            output_dir=args.output_dir,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Report saved to: {path}")


if __name__ == "__main__":
    main()
