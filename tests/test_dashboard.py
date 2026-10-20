"""Behavior tests from the outline plus date, export, and empty-result edges."""

import copy
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import matplotlib.pyplot as plt
import numpy as np

from src.catalog_adapter import load_catalog, records_at_reference_date
from src.constants import DEFAULT_CATALOG_PATH, DEFAULT_REFERENCE_DATE, PLOT_FILENAMES, WORKLIST_CSV_COLUMNS
from src.counters import count_by_product, count_by_vendor, count_summary_stats, find_data_quality_issues
from src.dashboard import generate_dashboard, main
from src.export import export_worklist_csv
from src.filters import (
    filter_by_date_range, filter_by_due_status, filter_by_product,
    filter_by_ransomware, filter_by_vendor,
)
from src.plots import plot_monthly_trend
from src.prioritizer import PrioritizedWorklist
from src.test_data import FAKE_CATALOG_INFO, FAKE_RECORDS
from src.verification import export_verification_sample


def ids(records):
    return [record.cve_id for record in records]


class FilterTests(unittest.TestCase):
    def test_exact_case_insensitive_vendor_and_product(self):
        self.assertEqual(ids(filter_by_vendor(FAKE_RECORDS, "testvendor")),
                         ["CVE-FAKE-001", "CVE-FAKE-002", "CVE-FAKE-009"])
        self.assertEqual(len(filter_by_product(FAKE_RECORDS, "pRoductA")), 3)
        self.assertEqual(filter_by_vendor(FAKE_RECORDS, "Test"), [])
        self.assertEqual(filter_by_product(FAKE_RECORDS, "absent"), [])

    def test_ransomware_known_and_unknown(self):
        self.assertEqual(ids(filter_by_ransomware(FAKE_RECORDS, "known")),
                         ["CVE-FAKE-001", "CVE-FAKE-003", "CVE-FAKE-006"])
        self.assertEqual(len(filter_by_ransomware(FAKE_RECORDS, "Unknown")), 7)
        with self.assertRaises(ValueError):
            filter_by_ransomware(FAKE_RECORDS, "safe")

    def test_due_boundaries(self):
        base = records_at_reference_date(FAKE_RECORDS[:1], DEFAULT_REFERENCE_DATE)[0]
        records = [
            replace(base, cve_id=str(days), days_until_due=days,
                    due_date=DEFAULT_REFERENCE_DATE + timedelta(days=days), is_overdue=days < 0)
            for days in [-1, 0, 7, 8]
        ]
        records += [replace(base, cve_id="none", days_until_due=None, due_date=None, is_overdue=False)]
        self.assertEqual(ids(filter_by_due_status(records, "overdue")), ["-1"])
        self.assertEqual(ids(filter_by_due_status(records, "due_soon")), ["0", "7"])
        self.assertEqual(ids(filter_by_due_status(records, "not_yet_due")), ["8"])
        with self.assertRaises(ValueError):
            filter_by_due_status([], "soon")

    def test_date_range_inclusive_and_open_ends(self):
        self.assertEqual(len(filter_by_date_range(FAKE_RECORDS, date(2026, 10, 1), date(2026, 10, 16))), 5)
        self.assertEqual(ids(filter_by_date_range(FAKE_RECORDS, end_date=date(2026, 6, 1))), ["CVE-FAKE-008"])
        self.assertEqual(ids(filter_by_date_range(FAKE_RECORDS, start_date=date(2026, 10, 16))), ["CVE-FAKE-009"])
        self.assertEqual(len(filter_by_date_range(FAKE_RECORDS)), 9)
        with self.assertRaises(ValueError):
            filter_by_date_range([], date(2026, 10, 2), date(2026, 10, 1))

    def test_filters_return_new_lists_without_changing_records(self):
        before = copy.deepcopy([vars(r) for r in FAKE_RECORDS])
        selected = filter_by_vendor(FAKE_RECORDS, "TestVendor")
        selected.clear()
        self.assertEqual([vars(r) for r in FAKE_RECORDS], before)


class WorklistTests(unittest.TestCase):
    def setUp(self):
        self.worklist = PrioritizedWorklist(FAKE_RECORDS, FAKE_CATALOG_INFO)

    def test_exact_outline_sort_order(self):
        self.assertEqual(ids(self.worklist.get_records()), [
            f"CVE-FAKE-{number:03d}" for number in [1, 2, 9, 3, 4, 10, 5, 6, 8, 7]
        ])
        self.assertEqual(len(self.worklist), 10)
        self.assertEqual(FAKE_RECORDS[0].cve_id, "CVE-FAKE-001")

    def test_ties_remain_stable(self):
        record = records_at_reference_date(FAKE_RECORDS[:1], DEFAULT_REFERENCE_DATE)[0]
        tied = [replace(record, cve_id="second"), replace(record, cve_id="first")]
        self.assertEqual(ids(PrioritizedWorklist(tied, {}).records), ["second", "first"])

    def test_summary_matches_hand_calculated_values(self):
        stats = self.worklist.summary_stats()
        for key, expected in {
            "total": 10, "overdue_count": 2, "due_soon_count": 4,
            "not_yet_due_count": 2, "no_due_date_count": 2, "ransomware_known_count": 3,
            "mean_age_days": 45.0, "median_age_days": 17.0, "mean_days_until_due": 10.125,
        }.items():
            self.assertEqual(stats[key], expected, key)

    def test_empty_and_all_missing_statistics(self):
        stats = PrioritizedWorklist([], {}).summary_stats()
        self.assertEqual(stats["total"], 0)
        self.assertIsNone(stats["mean_age_days"])
        self.assertIsNone(stats["median_age_days"])
        self.assertIsNone(stats["mean_days_until_due"])
        record = records_at_reference_date(FAKE_RECORDS[:1], DEFAULT_REFERENCE_DATE)[0]
        record = replace(record, due_date=None, date_added=None, age_days=None,
                         days_until_due=None, is_overdue=False)
        stats = PrioritizedWorklist([record], {}).summary_stats()
        self.assertEqual(stats["no_due_date_count"], 1)
        self.assertIsNone(stats["mean_age_days"])

    def test_worklist_copies_metadata_and_list(self):
        metadata, filters = dict(FAKE_CATALOG_INFO), ["test"]
        worklist = PrioritizedWorklist(FAKE_RECORDS, metadata, filters)
        worklist.get_records().clear()
        metadata["catalog_version"] = "changed"
        filters.clear()
        self.assertEqual(len(worklist), 10)
        self.assertEqual(worklist.catalog_info["catalog_version"], "TEST-1.0")
        self.assertEqual(worklist.applied_filters, ["test"])


class CounterTests(unittest.TestCase):
    def test_vendor_and_product_counts(self):
        self.assertEqual(count_by_vendor(FAKE_RECORDS),
                         {"BigCorp": 3, "TestVendor": 3, "AnotherVendor": 2, "SmallCo": 2})
        self.assertEqual(count_by_product(FAKE_RECORDS)["ProductA"], 3)
        self.assertEqual(count_by_product(FAKE_RECORDS)["ProductD"], 2)
        self.assertEqual(list(count_by_vendor(FAKE_RECORDS))[:2], ["BigCorp", "TestVendor"])

    def test_numpy_count_statistics(self):
        self.assertEqual(count_summary_stats({"A": 3, "B": 2, "C": 3, "D": 2}),
                         {"max": 3.0, "min": 2.0, "mean": 2.5, "median": 2.5, "std_dev": 0.5})
        self.assertTrue(all(value is None for value in count_summary_stats({}).values()))

    def test_quality_reports_unique_duplicate_ids(self):
        issues = find_data_quality_issues(FAKE_RECORDS + [FAKE_RECORDS[0], FAKE_RECORDS[0]])
        self.assertEqual(issues["missing_date_added"], ["CVE-FAKE-010"])
        self.assertEqual(issues["missing_due_date"], ["CVE-FAKE-007", "CVE-FAKE-008"])
        self.assertEqual(issues["duplicate_cve_ids"], ["CVE-FAKE-001"])
        self.assertEqual(issues["total_issues"], 4)


class AdapterTests(unittest.TestCase):
    def test_override_copies_and_recalculates(self):
        before = copy.deepcopy([vars(record) for record in FAKE_RECORDS])
        records = records_at_reference_date(FAKE_RECORDS, date(2026, 10, 20))
        self.assertEqual(records[2].days_until_due, 0)
        self.assertFalse(records[2].is_overdue)
        self.assertEqual(records[8].days_until_due, -1)
        self.assertTrue(records[8].is_overdue)
        self.assertIsNone(records[9].age_days)
        records[0].cwes.append("extra")
        self.assertEqual([vars(record) for record in FAKE_RECORDS], before)

    def test_leap_day_and_year_boundary(self):
        record = copy.deepcopy(FAKE_RECORDS[0])
        record.date_added, record.due_date = date(2024, 2, 28), date(2024, 3, 1)
        leap = records_at_reference_date([record], date(2024, 2, 29))[0]
        self.assertEqual((leap.age_days, leap.days_until_due), (1, 1))
        record.date_added, record.due_date = date(2025, 12, 31), date(2026, 1, 2)
        january = records_at_reference_date([record], date(2026, 1, 1))[0]
        self.assertEqual((january.age_days, january.days_until_due), (1, 1))

    def test_invalid_catalogs_and_missing_dates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text(json.dumps({"count": 1, "vulnerabilities": []}))
            with self.assertRaisesRegex(ValueError, "count"):
                load_catalog(path)
            row = {"cveID": "CVE-TEST", "dateAdded": "2026-02-30"}
            path.write_text(json.dumps({"count": 1, "vulnerabilities": [row]}))
            with self.assertRaisesRegex(ValueError, "CVE-TEST: invalid dateAdded"):
                load_catalog(path)
            row["dateAdded"] = None
            path.write_text(json.dumps({"count": 1, "vulnerabilities": [row]}))
            records, info = load_catalog(path)
            self.assertIsNone(records[0].age_days)
            self.assertIsNone(records[0].days_until_due)
            self.assertFalse(records[0].is_overdue)
            self.assertEqual(info["download_date"], "Unknown")

    def test_real_catalog_dates_and_count(self):
        records, info = load_catalog(DEFAULT_CATALOG_PATH)
        self.assertEqual(len(records), 1748)
        self.assertEqual(info["catalog_version"], "2026.10.16")
        self.assertEqual(find_data_quality_issues(records)["total_issues"], 0)
        reference = DEFAULT_REFERENCE_DATE.toordinal()
        for record in records:
            self.assertEqual(record.age_days, reference - record.date_added.toordinal())
            self.assertEqual(record.days_until_due, record.due_date.toordinal() - reference)
            self.assertEqual(record.is_overdue, record.due_date < DEFAULT_REFERENCE_DATE)


class OutputTests(unittest.TestCase):
    def test_csv_round_trip_quotes_newlines_and_missing_dates(self):
        records = records_at_reference_date(FAKE_RECORDS, DEFAULT_REFERENCE_DATE)
        records[0] = replace(records[0], required_action='Apply "patch", then\nrestart')
        worklist = PrioritizedWorklist(records, FAKE_CATALOG_INFO)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "worklist.csv"
            export_worklist_csv(worklist, path)
            with path.open(newline="", encoding="utf-8") as stream:
                self.assertIn("Reference date: 2026-10-18", stream.readline())
                reader = csv.DictReader(stream)
                self.assertEqual(reader.fieldnames, WORKLIST_CSV_COLUMNS)
                rows = list(reader)
            self.assertEqual([row["cve_id"] for row in rows], ids(worklist.records))
            self.assertEqual(rows[0]["required_action"], 'Apply "patch", then\nrestart')
            self.assertEqual(rows[0]["due_date"], "2026-10-10")
            self.assertEqual(rows[-1]["due_date"], "")
            self.assertEqual(rows[-1]["days_until_due"], "")

    def test_complete_filtered_and_empty_dashboard_outputs(self):
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
                files = list(Path(directory).iterdir())
                self.assertEqual(len(files), 6)
                for name in PLOT_FILENAMES:
                    pixels = plt.imread(Path(directory) / name)
                    self.assertGreater(pixels.shape[0], 500)
                    self.assertGreater(float(np.std(pixels)), 0.01)
                self.assertEqual(plt.get_fignums(), [])
                with (Path(directory) / "prioritized_worklist_2026-10-18.csv").open() as stream:
                    stream.readline()
                    rows = list(csv.DictReader(stream))
                self.assertEqual(len(rows), expected)
                self.assertTrue(all(row["vendor"] == "TestVendor" for row in rows))
        self.assertEqual([vars(record) for record in FAKE_RECORDS], before)

    def test_override_applies_before_due_status_filter(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            path = generate_dashboard(
                FAKE_RECORDS, FAKE_CATALOG_INFO, date(2026, 10, 20),
                due_status_filter="overdue", output_dir=directory
            )
            self.assertIn("overdue_count: 3", Path(path).read_text())
            self.assertIn("Reference date: 2026-10-20", Path(path).read_text())
        self.assertEqual(FAKE_CATALOG_INFO["reference_date"], "2026-10-18")

    def test_monthly_chart_includes_zero_months(self):
        records = records_at_reference_date(FAKE_RECORDS[:2], DEFAULT_REFERENCE_DATE)
        records = [replace(records[0], date_added=date(2026, 1, 1)),
                   replace(records[1], date_added=date(2026, 3, 1))]
        with patch("src.plots._save") as save:
            plot_monthly_trend(records, FAKE_CATALOG_INFO, "unused.png")
            fig = save.call_args.args[0]
            try:
                self.assertEqual([bar.get_height() for bar in fig.axes[0].patches], [1, 0, 1])
            finally:
                plt.close(fig)

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

    def test_verification_sample_unique_reproducible_and_checks_mismatches(self):
        records, _ = load_catalog(DEFAULT_CATALOG_PATH)
        with tempfile.TemporaryDirectory() as directory:
            path = export_verification_sample(records, directory)
            original = path.read_bytes()
            export_verification_sample(records, directory)
            self.assertEqual(path.read_bytes(), original)
            with path.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 30)
            self.assertEqual(len({row["cve_id"] for row in rows}), 30)
            self.assertTrue(all(row["match?"] == "yes" for row in rows))
            records[0] = replace(records[0], age_days=-999)
            path = export_verification_sample(records, directory)
            with path.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]["match?"], "no")


if __name__ == "__main__":
    unittest.main()
