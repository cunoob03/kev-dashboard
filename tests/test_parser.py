"""Parser/date tests using eight fake records and Python's built-in unittest.

Run from the repository root:
    python -m unittest discover -s tests -p "test_parser.py" -v
"""

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from src import config
from src.models import VulnerabilityRecord
from src.parser import find_data_quality_issues, load_catalog, parse_date


def make_fake_row(cve_id, due_date, date_added="2026-10-01"):
    """Create all twelve source fields; these are invented TEST records only."""
    return {
        "cveID": cve_id,
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Fake vulnerability for testing",
        "dateAdded": date_added,
        "shortDescription": "This is a fake record, not a real advisory.",
        "requiredAction": "Example action for testing.",
        "dueDate": due_date,
        "knownRansomwareCampaignUse": "Unknown",
        "forensicTriage": "Yes",
        "notes": "Test data only.",
        "cwes": ["CWE-79"],
    }


# Reference: 2026-10-18. All dates below are hand-selected for boundary checks.
FAKE_RECORDS = [
    make_fake_row("CVE-2026-0001", "2026-10-17"),  # Yesterday: overdue.
    make_fake_row("CVE-2026-0002", "2026-10-18"),  # Today: due soon.
    make_fake_row("CVE-2026-0003", "2026-10-25"),  # Seven days: due soon.
    make_fake_row("CVE-2026-0004", "2026-11-01"),  # Fourteen days: due soon.
    make_fake_row("CVE-2026-0005", "2026-11-02"),  # Fifteen days: not yet due.
    make_fake_row("CVE-2026-0006", None),          # Missing due date.
    make_fake_row("CVE-2026-0007", "2026-10-20", "2026-02-30"),  # Invalid date.
    make_fake_row("CVE-2026-0001", "2026-10-21"),  # Duplicate ID; retain it.
]


class ParserTests(unittest.TestCase):
    """Each test gets a temporary input file, never the frozen catalog."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "fake_catalog.json"

    def write_catalog(self, rows, count=None):
        if count is None:
            count = len(rows)
        catalog = {
            "title": "Fake KEV catalog for tests",
            "catalogVersion": "TEST-1.0",
            "dateReleased": "2026-10-18T00:00:00Z",
            "count": count,
            "vulnerabilities": rows,
        }
        self.path.write_text(json.dumps(catalog), encoding="utf-8")

    def test_valid_dates(self):
        self.assertEqual(parse_date("2026-10-18"), date(2026, 10, 18))
        self.assertEqual(parse_date(" 2024-02-29 "), date(2024, 2, 29))

    def test_missing_bad_and_wrong_type_dates(self):
        values = [None, "", "  ", "2026-02-30", "2025-02-29", "2026-13-01",
                  "18/10/2026", "20261018", "2026-W42-7", 123, False, [], {}]
        for value in values:
            self.assertIsNone(parse_date(value), msg=repr(value))

    def test_fake_catalog_metadata_and_all_twelve_fields(self):
        self.write_catalog(FAKE_RECORDS)
        metadata, records = load_catalog(self.path)
        self.assertEqual(metadata["catalog_version"], "TEST-1.0")
        self.assertEqual(metadata["date_released"], "2026-10-18T00:00:00Z")
        self.assertEqual(metadata["record_count"], 8)
        self.assertEqual(metadata["declared_record_count"], 8)
        self.assertEqual(metadata["file_name"], "fake_catalog.json")
        self.assertIsNone(metadata["download_date"])
        self.assertEqual(metadata["file_issues"], [])
        record = records[0]
        self.assertIsInstance(record, VulnerabilityRecord)
        self.assertEqual(record.cve_id, "CVE-2026-0001")
        self.assertEqual(record.vendor_project, "Example Vendor")
        self.assertEqual(record.product, "Example Product")
        self.assertEqual(record.vulnerability_name, "Fake vulnerability for testing")
        self.assertEqual(record.date_added, date(2026, 10, 1))
        self.assertEqual(record.short_description, "This is a fake record, not a real advisory.")
        self.assertEqual(record.required_action, "Example action for testing.")
        self.assertEqual(record.due_date, date(2026, 10, 17))
        self.assertEqual(record.known_ransomware_campaign_use, "Unknown")
        self.assertEqual(record.forensic_triage, "Yes")
        self.assertEqual(record.notes, "Test data only.")
        self.assertEqual(record.cwes, ["CWE-79"])

    def test_fake_date_math_and_four_statuses(self):
        self.write_catalog(FAKE_RECORDS)
        metadata, records = load_catalog(self.path)
        expected_days = [-1, 0, 7, 14, 15, None, 2, 3]
        expected_statuses = [
            "overdue", "due_soon", "due_soon", "due_soon",
            "not_yet_due", "no_due_date", "due_soon", "due_soon",
        ]
        for index, record in enumerate(records):
            self.assertEqual(record.days_until_due(), expected_days[index])
            self.assertEqual(record.due_status(), expected_statuses[index])
            if index == 6:
                self.assertIsNone(record.age_in_days())
            else:
                self.assertEqual(record.age_in_days(), 17)

    def test_quality_flags_and_duplicate_positions(self):
        self.write_catalog(FAKE_RECORDS)
        metadata, records = load_catalog(self.path)
        issues = find_data_quality_issues(records)
        self.assertEqual(len(records), 8)  # Duplicates have not been removed.
        self.assertEqual(issues["missing_due_date"],
                         [{"record_number": 6, "cve_id": "CVE-2026-0006"}])
        self.assertEqual(issues["missing_date_added"],
                         [{"record_number": 7, "cve_id": "CVE-2026-0007"}])
        self.assertEqual(issues["duplicate_cve_ids"], {"CVE-2026-0001": [1, 8]})
        self.assertEqual(issues["invalid_records"][0]["record_number"], 7)
        self.assertIn("dateAdded", issues["invalid_records"][0]["messages"][0])
        # Missing due + unavailable added date + invalid date message + duplicate ID.
        self.assertEqual(issues["total_issues"], 4)
        self.assertEqual(issues["affected_record_count"], 4)

    def test_reference_date_override_does_not_change_record(self):
        record = VulnerabilityRecord(date_added=date(2026, 10, 16),
                                     due_date=date(2026, 10, 19))
        self.assertEqual(record.age_in_days(), 2)
        self.assertEqual(record.days_until_due(), 1)
        self.assertEqual(record.due_status(), "due_soon")
        self.assertEqual(record.age_in_days(date(2026, 10, 20)), 4)
        self.assertEqual(record.days_until_due(date(2026, 10, 20)), -1)
        self.assertEqual(record.due_status(date(2026, 10, 20)), "overdue")
        self.assertEqual(record.due_date, date(2026, 10, 19))
        self.assertEqual(record.days_until_due(), 1)

    def test_due_soon_setting_is_read_from_shared_config(self):
        original = config.DUE_SOON_DAYS
        record = VulnerabilityRecord(due_date=date(2026, 10, 28))
        try:
            config.DUE_SOON_DAYS = 7
            self.assertEqual(record.due_status(), "not_yet_due")
            config.DUE_SOON_DAYS = 14
            self.assertEqual(record.due_status(), "due_soon")
        finally:
            config.DUE_SOON_DAYS = original

    def test_leap_day_year_boundary_and_negative_age(self):
        leap = VulnerabilityRecord(date_added=date(2024, 2, 28), due_date=date(2024, 3, 1))
        self.assertEqual(leap.age_in_days(date(2024, 2, 29)), 1)
        self.assertEqual(leap.days_until_due(date(2024, 2, 29)), 1)
        new_year = VulnerabilityRecord(date_added=date(2025, 12, 31), due_date=date(2026, 1, 2))
        self.assertEqual(new_year.age_in_days(date(2026, 1, 1)), 1)
        self.assertEqual(new_year.days_until_due(date(2026, 1, 1)), 1)
        self.assertEqual(new_year.age_in_days(date(2025, 12, 30)), -1)

    def test_missing_dates_are_safe(self):
        record = VulnerabilityRecord()
        self.assertIsNone(record.age_in_days())
        self.assertIsNone(record.days_until_due())
        self.assertEqual(record.due_status(), "no_due_date")

    def test_missing_and_blank_required_fields_become_none(self):
        row = make_fake_row("CVE-2026-0001", "")
        del row["cveID"]
        row["vendorProject"] = " "
        row["product"] = ""
        row["dateAdded"] = None
        row["notes"] = ""
        self.write_catalog([row])
        metadata, records = load_catalog(self.path)
        record = records[0]
        for value in [record.cve_id, record.vendor_project, record.product,
                      record.date_added, record.due_date, record.notes]:
            self.assertIsNone(value)
        self.assertEqual(find_data_quality_issues(records)["total_issues"], 5)

    def test_invalid_values_and_later_valid_record_are_both_retained(self):
        row = make_fake_row("not-a-cve", "bad-date")
        row["vendorProject"] = 12
        row["product"] = []
        row["forensicTriage"] = False
        row["cwes"] = ["CWE-79", 123]
        self.write_catalog([row, FAKE_RECORDS[0]])
        metadata, records = load_catalog(self.path)
        self.assertEqual(len(records), 2)
        bad = records[0]
        for value in [bad.cve_id, bad.due_date, bad.vendor_project,
                      bad.product, bad.forensic_triage, bad.cwes]:
            self.assertIsNone(value)
        self.assertEqual(len(bad.validation_issues), 6)
        self.assertEqual(records[1].cve_id, "CVE-2026-0001")

    def test_non_object_rows_are_retained_with_diagnostics(self):
        self.write_catalog([None, 17, "bad row", [], {}, FAKE_RECORDS[0]])
        metadata, records = load_catalog(self.path)
        self.assertEqual(len(records), 6)
        self.assertEqual(len(find_data_quality_issues(records)["invalid_records"]), 4)
        self.assertEqual(records[5].cve_id, "CVE-2026-0001")

    def test_missing_ids_are_not_counted_as_duplicate_cves(self):
        self.write_catalog([{}, {}])
        metadata, records = load_catalog(self.path)
        issues = find_data_quality_issues(records)
        self.assertEqual(len(issues["missing_cve_id"]), 2)
        self.assertEqual(issues["duplicate_cve_ids"], {})

    def test_empty_cwe_list_is_valid_and_lists_are_not_shared(self):
        row = make_fake_row("CVE-2026-0001", None)
        row["cwes"] = []
        self.write_catalog([row])
        metadata, records = load_catalog(self.path)
        self.assertEqual(records[0].cwes, [])
        labels = ["CWE-79"]
        first = VulnerabilityRecord(cwes=labels)
        second = VulnerabilityRecord(cwes=labels)
        labels.append("CWE-22")
        first.validation_issues.append("Example diagnostic")
        self.assertEqual(first.cwes, ["CWE-79"])
        self.assertEqual(second.validation_issues, [])

    def test_count_mismatch_is_reported_without_losing_records(self):
        self.write_catalog(FAKE_RECORDS, count=99)
        metadata, records = load_catalog(self.path)
        self.assertEqual(metadata["declared_record_count"], 99)
        self.assertEqual(metadata["record_count"], 8)
        self.assertEqual(len(records), 8)
        self.assertIn("Declared count does not match", metadata["file_issues"][0])

    def test_boolean_count_is_invalid(self):
        self.write_catalog([FAKE_RECORDS[0]], count=True)
        metadata, records = load_catalog(self.path)
        self.assertIsNone(metadata["declared_record_count"])
        self.assertTrue(metadata["file_issues"])
        self.assertEqual(len(records), 1)

    def test_unreadable_malformed_and_wrong_shape_files_report_errors(self):
        # The file has not been created yet.
        metadata, records = load_catalog(self.path)
        self.assertEqual(records, [])
        self.assertTrue(metadata["file_issues"])
        for content in ["{bad JSON", "[]", '{"vulnerabilities": null}', '{"vulnerabilities": {}}']:
            self.path.write_text(content, encoding="utf-8")
            metadata, records = load_catalog(self.path)
            self.assertEqual(records, [])
            self.assertTrue(metadata["file_issues"])
        self.path.write_bytes(b"\xff")
        metadata, records = load_catalog(self.path)
        self.assertEqual(records, [])
        self.assertTrue(metadata["file_issues"])

    def test_empty_catalog_has_no_record_issues(self):
        self.write_catalog([])
        metadata, records = load_catalog(self.path)
        self.assertEqual(metadata["file_issues"], [])
        self.assertEqual(records, [])
        self.assertEqual(find_data_quality_issues(records)["total_issues"], 0)

    def test_quality_reporting_does_not_change_records(self):
        self.write_catalog(FAKE_RECORDS)
        metadata, records = load_catalog(self.path)
        issues = find_data_quality_issues(records)
        issues["invalid_records"][0]["messages"].clear()
        repeated = find_data_quality_issues(records)
        self.assertEqual(repeated["total_issues"], 4)
        self.assertEqual(len(records), 8)


if __name__ == "__main__":
    unittest.main()
