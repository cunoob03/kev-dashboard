"""Unit and integration tests using the canonical parser records and date rules."""

import copy
import csv
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import numpy as np

from src import config
from src.constants import PLOT_FILENAMES, WORKLIST_CSV_COLUMNS
from src.counters import count_by_product, count_by_vendor, count_summary_stats
from src.dashboard import generate_dashboard, main
from src.export import export_worklist_csv
from src.filters import (
    filter_by_date_range, filter_by_due_status, filter_by_product,
    filter_by_ransomware, filter_by_vendor,
)
from src.models import VulnerabilityRecord
from src.parser import find_data_quality_issues, load_catalog
from src.plots import plot_due_status, plot_monthly_trend, plot_ransomware_by_vendor
from src.prioritizer import PrioritizedWorklist
from src.sample_check import print_sample
from src.sampling import sample_positions
from src.test_data import FAKE_CATALOG_INFO, FAKE_RECORDS
from src.verification import export_verification_sample

# Import after src.plots has selected the headless backend.
import matplotlib.pyplot as plt


def ids(records):
    return [record.cve_id for record in records]


def changed(record, **values):
    result = copy.deepcopy(record)
    for name, value in values.items():
        setattr(result, name, value)
    return result


def read_worklist(path):
    with Path(path).open(newline="", encoding="utf-8") as stream:
        provenance = stream.readline()
        reader = csv.DictReader(stream)
        return provenance, reader.fieldnames, list(reader)


def raw_record(cve_id="CVE-2026-0001", due_date="2026-11-01", vendor="Example Vendor"):
    return {
        "cveID": cve_id, "vendorProject": vendor, "product": "Example Product",
        "vulnerabilityName": "Test vulnerability", "dateAdded": "2026-10-01",
        "shortDescription": "Test only", "requiredAction": "Apply example update",
        "dueDate": due_date, "knownRansomwareCampaignUse": "Known",
        "forensicTriage": "Yes", "notes": "Test source", "cwes": ["CWE-79"],
    }


def write_catalog(path, rows, count=None):
    catalog = {
        "title": "Integration test catalog", "catalogVersion": "TEST-2.0",
        "dateReleased": "2026-10-18T00:00:00Z",
        "count": len(rows) if count is None else count, "vulnerabilities": rows,
    }
    Path(path).write_text(json.dumps(catalog), encoding="utf-8")


class FilterTests(unittest.TestCase):
    def test_exact_case_insensitive_vendor_and_product(self):
        self.assertEqual(ids(filter_by_vendor(FAKE_RECORDS, "testvendor")),
                         ["CVE-FAKE-001", "CVE-FAKE-002", "CVE-FAKE-009"])
        self.assertEqual(len(filter_by_product(FAKE_RECORDS, "pRoductA")), 3)
        self.assertEqual(filter_by_vendor(FAKE_RECORDS, "Test"), [])
        self.assertEqual(filter_by_product(FAKE_RECORDS, "absent"), [])

    def test_ransomware_and_missing_text(self):
        records = FAKE_RECORDS + [VulnerabilityRecord()]
        self.assertEqual(ids(filter_by_ransomware(records, "known")),
                         ["CVE-FAKE-001", "CVE-FAKE-003", "CVE-FAKE-006"])
        self.assertEqual(len(filter_by_ransomware(records, "Unknown")), 7)
        self.assertEqual(len(filter_by_vendor(records, "TestVendor")), 3)
        self.assertEqual(len(filter_by_product(records, "ProductA")), 3)
        with self.assertRaises(ValueError):
            filter_by_ransomware(records, "safe")

    def test_due_boundaries_and_missing_date(self):
        records = [
            VulnerabilityRecord(cve_id=str(days),
                                due_date=config.DEFAULT_REFERENCE_DATE + timedelta(days=days))
            for days in [-1, 0, 7, 8, 14, 15]
        ] + [VulnerabilityRecord(cve_id="none")]
        self.assertEqual(ids(filter_by_due_status(records, "overdue")), ["-1"])
        self.assertEqual(ids(filter_by_due_status(records, "due_soon")), ["0", "7", "8", "14"])
        self.assertEqual(ids(filter_by_due_status(records, "not_yet_due")), ["15"])
        self.assertEqual(ids(filter_by_due_status(records, "no_due_date")), ["none"])
        with self.assertRaises(ValueError):
            filter_by_due_status([], "soon")

    def test_date_range_inclusive_and_open_ends(self):
        self.assertEqual(len(filter_by_date_range(FAKE_RECORDS, date(2026, 10, 1), date(2026, 10, 16))), 5)
        self.assertEqual(ids(filter_by_date_range(FAKE_RECORDS, end_date=date(2026, 6, 1))), ["CVE-FAKE-008"])
        self.assertEqual(ids(filter_by_date_range(FAKE_RECORDS, start_date=date(2026, 10, 16))), ["CVE-FAKE-009"])
        self.assertEqual(len(filter_by_date_range(FAKE_RECORDS)), 9)
        with self.assertRaises(ValueError):
            filter_by_date_range([], date(2026, 10, 2), date(2026, 10, 1))

    def test_filters_return_new_lists_without_mutating_records(self):
        before = copy.deepcopy([vars(r) for r in FAKE_RECORDS])
        selected = filter_by_vendor(FAKE_RECORDS, "TestVendor")
        selected.clear()
        self.assertEqual([vars(r) for r in FAKE_RECORDS], before)


class WorklistTests(unittest.TestCase):
    def test_exact_sort_order_and_no_mutation(self):
        before = copy.deepcopy([vars(r) for r in FAKE_RECORDS])
        worklist = PrioritizedWorklist(FAKE_RECORDS, FAKE_CATALOG_INFO)
        self.assertEqual(ids(worklist.get_records()), [
            f"CVE-FAKE-{number:03d}" for number in [1, 2, 9, 3, 4, 10, 5, 6, 8, 7]
        ])
        self.assertEqual(len(worklist), 10)
        self.assertEqual([vars(r) for r in FAKE_RECORDS], before)

    def test_ties_remain_stable(self):
        tied = [changed(FAKE_RECORDS[0], cve_id="second"), changed(FAKE_RECORDS[0], cve_id="first")]
        self.assertEqual(ids(PrioritizedWorklist(tied, {}).records), ["second", "first"])

    def test_summary_matches_hand_calculated_values(self):
        stats = PrioritizedWorklist(FAKE_RECORDS, FAKE_CATALOG_INFO).summary_stats()
        self.assertEqual(stats, {
            "total": 10, "overdue_count": 2, "due_soon_count": 4,
            "not_yet_due_count": 2, "no_due_date_count": 2, "ransomware_known_count": 3,
            "mean_age_days": 45.0, "median_age_days": 17.0, "mean_days_until_due": 10.125,
        })

    def test_empty_and_all_missing_statistics(self):
        stats = PrioritizedWorklist([], {}).summary_stats()
        self.assertEqual(stats["total"], 0)
        for key in ["mean_age_days", "median_age_days", "mean_days_until_due"]:
            self.assertIsNone(stats[key])
        stats = PrioritizedWorklist([VulnerabilityRecord()], {}).summary_stats()
        self.assertEqual(stats["no_due_date_count"], 1)
        self.assertEqual(stats["ransomware_known_count"], 0)
        self.assertIsNone(stats["mean_age_days"])

    def test_copies_metadata_and_list_and_honors_reference_date(self):
        metadata, filters = dict(FAKE_CATALOG_INFO), ["test"]
        worklist = PrioritizedWorklist(FAKE_RECORDS, metadata, filters, date(2026, 10, 20))
        worklist.get_records().clear()
        metadata["catalog_version"] = "changed"
        filters.clear()
        self.assertEqual(len(worklist), 10)
        self.assertEqual(worklist.catalog_info["catalog_version"], "TEST-1.0")
        self.assertEqual(worklist.applied_filters, ["test"])
        self.assertEqual(worklist.catalog_info["reference_date"], "2026-10-20")
        self.assertEqual(worklist.summary_stats()["overdue_count"], 3)
        with self.assertRaises(ValueError):
            PrioritizedWorklist([], {}, reference_date="2026-10-20")


class CounterTests(unittest.TestCase):
    def test_vendor_and_product_counts_including_missing_fields(self):
        self.assertEqual(count_by_vendor(FAKE_RECORDS),
                         {"BigCorp": 3, "TestVendor": 3, "AnotherVendor": 2, "SmallCo": 2})
        self.assertEqual(count_by_product(FAKE_RECORDS)["ProductA"], 3)
        self.assertEqual(count_by_product(FAKE_RECORDS)["ProductD"], 2)
        self.assertEqual(list(count_by_vendor(FAKE_RECORDS))[:2], ["BigCorp", "TestVendor"])
        self.assertEqual(count_by_vendor([VulnerabilityRecord()]), {"(missing vendor)": 1})
        self.assertEqual(count_by_product([VulnerabilityRecord()]), {"(missing product)": 1})

    def test_numpy_count_statistics(self):
        self.assertEqual(count_summary_stats({"A": 3, "B": 2, "C": 3, "D": 2}),
                         {"max": 3.0, "min": 2.0, "mean": 2.5, "median": 2.5, "std_dev": 0.5})
        self.assertTrue(all(value is None for value in count_summary_stats({}).values()))

    def test_quality_report_uses_parser_duplicate_and_date_rules(self):
        issues = find_data_quality_issues(FAKE_RECORDS + [FAKE_RECORDS[0], FAKE_RECORDS[0]])
        self.assertEqual(issues["missing_date_added"], [{"record_number": 10, "cve_id": "CVE-FAKE-010"}])
        self.assertEqual(len(issues["missing_due_date"]), 2)
        self.assertEqual(issues["duplicate_cve_ids"], {"CVE-FAKE-001": [1, 11, 12]})
        self.assertEqual(issues["total_issues"], 4)


class OutputTests(unittest.TestCase):
    def test_csv_round_trip_quotes_newlines_and_missing_dates(self):
        records = copy.deepcopy(FAKE_RECORDS)
        records[0].required_action = 'Apply "patch", then\nrestart'
        worklist = PrioritizedWorklist(records, FAKE_CATALOG_INFO)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "worklist.csv"
            export_worklist_csv(worklist, path)
            provenance, columns, rows = read_worklist(path)
        self.assertIn("Reference date: 2026-10-18", provenance)
        self.assertIn("Download date: 2026-10-18", provenance)
        self.assertEqual(columns, WORKLIST_CSV_COLUMNS)
        self.assertEqual([row["cve_id"] for row in rows], ids(worklist.records))
        self.assertEqual(rows[0]["required_action"], 'Apply "patch", then\nrestart')
        self.assertEqual(rows[0]["due_date"], "2026-10-10")
        self.assertEqual(rows[-1]["due_date"], "")
        self.assertEqual(rows[-1]["days_until_due"], "")

    def test_complete_filtered_and_empty_outputs(self):
        before = copy.deepcopy([vars(record) for record in FAKE_RECORDS])
        for vendor, expected in [("testvendor", 3), ("absent", 0)]:
            with self.subTest(vendor=vendor), tempfile.TemporaryDirectory() as directory:
                with redirect_stdout(io.StringIO()):
                    report_path = generate_dashboard(
                        FAKE_RECORDS, FAKE_CATALOG_INFO, vendor_filter=vendor, output_dir=directory
                    )
                report = Path(report_path).read_text()
                self.assertIn(f"total: {expected}\n", report)
                self.assertIn(f"vendor = {vendor}", report)
                self.assertIn("Counts reflect catalog presence", report)
                self.assertEqual(len(list(Path(directory).iterdir())), 6)
                for name in PLOT_FILENAMES:
                    pixels = plt.imread(Path(directory) / name)
                    self.assertGreater(pixels.shape[0], 500)
                    self.assertGreater(float(np.std(pixels)), 0.01)
                self.assertEqual(plt.get_fignums(), [])
                _, _, rows = read_worklist(Path(directory) / "prioritized_worklist_2026-10-18.csv")
                self.assertEqual(len(rows), expected)
                self.assertTrue(all(row["vendor"] == "TestVendor" for row in rows))
        self.assertEqual([vars(record) for record in FAKE_RECORDS], before)

    def test_override_applies_to_filter_statistics_csv_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            path = generate_dashboard(
                FAKE_RECORDS, FAKE_CATALOG_INFO, date(2026, 10, 20),
                due_status_filter="overdue", output_dir=directory
            )
            report = Path(path).read_text()
            self.assertIn("overdue_count: 3", report)
            self.assertIn("Reference date: 2026-10-20", report)
            provenance, _, rows = read_worklist(Path(directory) / "prioritized_worklist_2026-10-20.csv")
        self.assertEqual(len(rows), 3)
        self.assertIn("Reference date: 2026-10-20", provenance)
        self.assertEqual(rows[-1]["days_until_due"], "-1")
        self.assertEqual(rows[-1]["age_days"], "4")
        self.assertEqual(FAKE_CATALOG_INFO["reference_date"], "2026-10-18")

    def test_monthly_chart_includes_zero_months(self):
        records = [changed(FAKE_RECORDS[0], date_added=date(2026, 1, 1)),
                   changed(FAKE_RECORDS[1], date_added=date(2026, 3, 1))]
        with patch("src.plots._save") as save:
            plot_monthly_trend(records, FAKE_CATALOG_INFO, "unused.png")
            fig = save.call_args.args[0]
            try:
                self.assertEqual([bar.get_height() for bar in fig.axes[0].patches], [1, 0, 1])
            finally:
                plt.close(fig)

    def test_ransomware_chart_handles_missing_vendor_and_ransomware(self):
        records = [VulnerabilityRecord(), VulnerabilityRecord(known_ransomware_campaign_use="Known")]
        with patch("src.plots._save") as save:
            plot_ransomware_by_vendor(records, FAKE_CATALOG_INFO, "unused.png")
            fig = save.call_args.args[0]
            try:
                self.assertEqual([bar.get_height() for bar in fig.axes[0].patches], [1, 0])
                self.assertIn("excluded: 1", save.call_args.args[2])
            finally:
                plt.close(fig)

    def test_monthly_chart_handles_latest_valid_calendar_month(self):
        records = [VulnerabilityRecord(date_added=date(9999, 12, 31))]
        with patch("src.plots._save") as save:
            plot_monthly_trend(records, {}, "unused.png")
            fig = save.call_args.args[0]
            try:
                self.assertEqual([bar.get_height() for bar in fig.axes[0].patches], [1])
                self.assertEqual(fig.axes[0].get_xticklabels()[0].get_text(), "9999-12")
            finally:
                plt.close(fig)

    def test_shared_threshold_changes_model_filter_summary_chart_report_and_export(self):
        records = [VulnerabilityRecord(cve_id="CVE-2026-0001", due_date=date(2026, 10, 28))]
        with patch.object(config, "DUE_SOON_DAYS", 9):
            self.assertEqual(records[0].due_status(), "not_yet_due")
            self.assertEqual(filter_by_due_status(records, "due_soon"), [])
            worklist = PrioritizedWorklist(records, {})
            self.assertEqual(worklist.summary_stats()["not_yet_due_count"], 1)
            with patch("src.plots._save") as save:
                plot_due_status(worklist, {}, "unused.png")
                fig = save.call_args.args[0]
                try:
                    self.assertIn("0–9", fig.axes[0].get_xticklabels()[1].get_text())
                    self.assertEqual([bar.get_height() for bar in fig.axes[0].patches], [0, 0, 1])
                finally:
                    plt.close(fig)
            with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
                report = generate_dashboard(records, {}, output_dir=directory)
                self.assertIn("Due-soon window: 0–9 days", Path(report).read_text())
                provenance, _, rows = read_worklist(Path(directory) / "prioritized_worklist_2026-10-18.csv")
                self.assertIn("Due soon: 0-9 days", provenance)
                self.assertEqual(rows[0]["days_until_due"], "10")


class IntegrationTests(unittest.TestCase):
    def test_real_catalog_to_dashboard_without_adapter(self):
        info, records = load_catalog()
        self.assertIsInstance(records[0], VulnerabilityRecord)
        self.assertEqual(records[0].forensic_triage, "Yes")
        self.assertEqual(len(records), 1748)
        self.assertEqual(info["catalog_version"], "2026.10.16")
        self.assertEqual(find_data_quality_issues(records)["total_issues"], 0)
        for record in records:
            self.assertEqual(record.age_in_days(), config.DEFAULT_REFERENCE_DATE.toordinal() - record.date_added.toordinal())
            self.assertEqual(record.days_until_due(), record.due_date.toordinal() - config.DEFAULT_REFERENCE_DATE.toordinal())
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            report = generate_dashboard(records, info, vendor_filter="Microsoft", output_dir=directory)
            self.assertIn("total: 390\n", Path(report).read_text())
            self.assertIn("Full catalog entries: 1748", Path(report).read_text())
            _, _, rows = read_worklist(Path(directory) / "prioritized_worklist_2026-10-18.csv")
            self.assertEqual(len(rows), 390)
            self.assertTrue(all(row["vendor"] == "Microsoft" for row in rows))

    def test_cli_uses_tolerant_parser_preserves_bad_rows_and_reports_hidden_issues(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            rows = [raw_record(), raw_record(), raw_record("CVE-2026-0002", "bad-date", None), None]
            rows[2]["product"] = None
            rows[2]["knownRansomwareCampaignUse"] = None
            write_catalog(catalog, rows, count=99)
            output = Path(directory) / "all"
            with redirect_stdout(io.StringIO()):
                status = main(["--catalog", str(catalog), "--output-dir", str(output)])
            self.assertEqual(status, 1)
            _, _, exported = read_worklist(output / "prioritized_worklist_2026-10-18.csv")
            self.assertEqual(len(exported), 4)
            self.assertEqual(exported[-1]["cve_id"], "")
            report = (output / "dashboard_report_2026-10-18.txt").read_text()
            self.assertIn("Declared count does not match", report)
            self.assertIn("dueDate must be a valid date", report)
            self.assertIn('"duplicate_cve_ids"', report)
            self.assertIn("(missing vendor): 2", report)
            filtered = Path(directory) / "filtered"
            with redirect_stdout(io.StringIO()):
                status = main(["--catalog", str(catalog), "--vendor", "Example Vendor", "--output-dir", str(filtered)])
            report = (filtered / "dashboard_report_2026-10-18.txt").read_text()
            self.assertEqual(status, 1)
            self.assertIn("total: 2\n", report)
            self.assertIn('"record_number": 4', report)
            self.assertIn("dueDate must be a valid date", report)

    def test_cli_no_due_date_and_combined_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            rows = [raw_record(), raw_record("CVE-2026-0002", None)]
            write_catalog(catalog, rows)
            output = Path(directory) / "selected"
            with redirect_stdout(io.StringIO()):
                status = main(["--catalog", str(catalog), "--due-status", "no_due_date",
                               "--vendor", "EXAMPLE VENDOR", "--product", "Example Product",
                               "--ransomware", "known", "--start-date", "2026-10-01",
                               "--end-date", "2026-10-01", "--output-dir", str(output)])
            self.assertEqual(status, 1)  # Missing deadline is disclosed, with outputs retained.
            _, _, selected = read_worklist(output / "prioritized_worklist_2026-10-18.csv")
            self.assertEqual([row["cve_id"] for row in selected], ["CVE-2026-0002"])

    def test_cli_download_date_override_and_valid_empty_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            write_catalog(catalog, [])
            output = Path(directory) / "empty"
            with redirect_stdout(io.StringIO()):
                status = main(["--catalog", str(catalog), "--download-date", "2026-10-19", "--output-dir", str(output)])
            self.assertEqual(status, 0)
            self.assertIn("Download date: 2026-10-19", (output / "dashboard_report_2026-10-18.txt").read_text())
            self.assertEqual(len(list(output.iterdir())), 6)
            self.assertEqual(read_worklist(output / "prioritized_worklist_2026-10-18.csv")[2], [])

    def test_failed_load_does_not_create_successful_empty_report(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "bad.json"
            catalog.write_text("{broken JSON")
            output = Path(directory) / "should-not-exist"
            with patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    main(["--catalog", str(catalog), "--output-dir", str(output)])
            self.assertEqual(error.exception.code, 2)
            self.assertFalse(output.exists())
            info, records = load_catalog(catalog)
            self.assertFalse(info["load_succeeded"])
            with self.assertRaises(ValueError):
                generate_dashboard(records, info, output_dir=output)

    def test_cli_rejects_invalid_dates_and_ranges(self):
        for arguments in [
            ["--reference-date", "2026-02-30"],
            ["--start-date", "2026-10-20", "--end-date", "2026-10-18"],
            ["--due-status", "invalid"],
        ]:
            with self.subTest(arguments=arguments), patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as caught:
                    main(arguments)
                self.assertEqual(caught.exception.code, 2)


class VerificationTests(unittest.TestCase):
    def test_console_and_worksheet_select_same_rows_and_reference_date(self):
        info, records = load_catalog()
        with tempfile.TemporaryDirectory() as directory:
            reference = date(2026, 10, 20)
            path = export_verification_sample(records, directory, reference, info)
            original = path.read_bytes()
            export_verification_sample(records, directory, reference, info)
            self.assertEqual(path.read_bytes(), original)
            with path.open() as stream:
                rows = list(csv.DictReader(stream))
            console = io.StringIO()
            with redirect_stdout(console):
                status = print_sample(reference_date=reference)
            self.assertEqual(status, 0)
            console_positions = re.findall(r"source record (\d+)\)", console.getvalue())
            self.assertEqual([row["source_record"] for row in rows], console_positions)
            self.assertEqual(len(rows), 30)
            self.assertEqual(len(set(console_positions)), 30)
            self.assertTrue(all(row["match?"] == "yes" for row in rows))
            self.assertTrue(all(row["reference_date"] == "2026-10-20" for row in rows))
            self.assertTrue(all(row["catalog_version"] == "2026.10.16" for row in rows))
            self.assertTrue(all(row["download_date"] == "2026-10-18" for row in rows))
            first = records[sample_positions(records)[0]]
            with patch.object(first, "age_in_days", return_value=-999):
                path = export_verification_sample(records, directory, reference, info)
                with path.open() as stream:
                    self.assertEqual(next(csv.DictReader(stream))["match?"], "no")

    def test_missing_dates_duplicate_ids_and_empty_samples(self):
        records = [VulnerabilityRecord(cve_id="duplicate"), VulnerabilityRecord(cve_id="duplicate")]
        with tempfile.TemporaryDirectory() as directory:
            path = export_verification_sample(records, directory)
            with path.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["source_record"] for row in rows}, {"1", "2"})
            self.assertTrue(all(row["expected_status"] == "no_due_date" for row in rows))
            self.assertTrue(all(row["match?"] == "yes" for row in rows))
            self.assertIn("unavailable", (Path(directory) / "verification_math_2026-10-18.md").read_text())
            path = export_verification_sample([], directory)
            with path.open() as stream:
                self.assertEqual(list(csv.DictReader(stream)), [])


if __name__ == "__main__":
    unittest.main()
