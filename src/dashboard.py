"""Generate a text report, prioritized CSV, and four PNG charts."""

import argparse
import json
from datetime import date
from pathlib import Path

from . import config
from .parser import load_catalog, parse_date, find_data_quality_issues
from .constants import PLOT_FILENAMES
from .counters import (
    count_by_product, count_by_vendor, count_summary_stats,
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
        f"Download date: {catalog_info.get('download_date') or 'Unknown'}",
        f"Reference date: {catalog_info.get('reference_date', 'Unknown')}",
        f"Due-soon window: 0–{config.DUE_SOON_DAYS} days (inclusive)",
        f"Full catalog entries: {catalog_info.get('record_count', 'Unknown')}",
        "Applied filters: " + ("; ".join(applied_filters) if applied_filters else "None"),
        "",
        "SUMMARY — SELECTED RECORDS",
    ]
    lines.extend(f"{key}: {_number(value)}" for key, value in worklist.summary_stats().items())
    lines += [
        "", "DATA QUALITY — FULL INPUT CATALOG (before filters)",
        "Record numbers refer to the original input order, starting at 1.",
        "Issue flags can overlap; affected_record_count counts distinct rows.",
        "File/header issues: " + json.dumps(catalog_info.get("file_issues", []), ensure_ascii=False),
        json.dumps(data_quality_issues, indent=2, ensure_ascii=False),
    ]
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
        "Missing vendor/product labels are shown explicitly; source values remain None.",
        "All charts and the CSV use the same selected records as this report.",
        "",
        "OUTPUTS — alongside this report",
        f"prioritized_worklist_{catalog_info['reference_date']}.csv",
        *PLOT_FILENAMES,
        "",
    ]
    return "\n".join(lines)


def generate_dashboard(records, catalog_info, reference_date=config.DEFAULT_REFERENCE_DATE,
                       vendor_filter=None, product_filter=None,
                       ransomware_filter=None, due_status_filter=None,
                       start_date=None, end_date=None, output_dir=None):
    """Generate all six outputs, print the report, and return its path.

    Read the parser's objects directly without changing them. Every date method
    receives the same reference_date. Quality reporting includes the full input
    so filters cannot hide source problems. output_dir isolates separate runs.
    """
    reference = reference_date if reference_date is not None else config.DEFAULT_REFERENCE_DATE
    if type(reference) is not date:
        raise ValueError("reference_date must be a datetime.date")
    if catalog_info.get("load_succeeded") is False:
        raise ValueError("Catalog load failed: " + "; ".join(catalog_info.get("file_issues", [])))
    selected = list(records)
    info = dict(catalog_info)
    info.setdefault("record_count", len(records))
    info["reference_date"] = reference.isoformat()
    issues = find_data_quality_issues(records)
    applied = []
    for label, value, function in [
        ("vendor", vendor_filter, filter_by_vendor),
        ("product", product_filter, filter_by_product),
        ("ransomware", ransomware_filter, filter_by_ransomware),
    ]:
        if value is not None:
            selected = function(selected, value)
            applied.append(f"{label} = {value}")
    if due_status_filter is not None:
        selected = filter_by_due_status(selected, due_status_filter, reference)
        applied.append(f"due status = {due_status_filter}")
    if start_date is not None or end_date is not None:
        selected = filter_by_date_range(selected, start_date, end_date)
        applied.append(f"date_added = {start_date or 'any'} to {end_date or 'any'} (inclusive)")
    info["applied_filters"] = applied
    worklist = PrioritizedWorklist(selected, info, applied, reference_date=reference)
    vendors, products = count_by_vendor(selected), count_by_product(selected)
    destination = Path(output_dir) if output_dir is not None else config.PROJECT_ROOT / "outputs"
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
    parsed = parse_date(value)
    if parsed is None:
        raise argparse.ArgumentTypeError("expected a valid date in YYYY-MM-DD format")
    return parsed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=config.CATALOG_PATH)
    parser.add_argument("--reference-date", type=iso_date, default=config.DEFAULT_REFERENCE_DATE)
    parser.add_argument("--download-date", type=iso_date, help="Known catalog download date")
    parser.add_argument("--output-dir", type=Path, default=config.PROJECT_ROOT / "outputs")
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--ransomware", type=str.title, choices=["Known", "Unknown"])
    parser.add_argument("--due-status", choices=["overdue", "due_soon", "not_yet_due", "no_due_date"])
    parser.add_argument("--start-date", type=iso_date)
    parser.add_argument("--end-date", type=iso_date)
    args = parser.parse_args(argv)
    if args.start_date and args.end_date and args.start_date > args.end_date:
        parser.error("--start-date must not be after --end-date")
    try:
        info, records = load_catalog(args.catalog)
        if args.download_date is not None:
            info["download_date"] = args.download_date.isoformat()
        path = generate_dashboard(
            records, info, args.reference_date, args.vendor, args.product,
            args.ransomware, args.due_status, args.start_date, args.end_date,
            output_dir=args.output_dir,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Report saved to: {path}")
    if info["file_issues"] or find_data_quality_issues(records)["total_issues"]:
        print("Data-quality issues were found; review the report before using the worklist.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
