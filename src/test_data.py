"""
Fake KEV records for testing dashboard code.
10 records with known, hand-calculated values.
"""
import datetime

class FakeRecord:
    """Minimal stand-in for KEVRecord during testing."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

# Reference date for testing: 2026-10-18
REF_DATE = datetime.date(2026, 10, 18)

FAKE_RECORDS = [
    FakeRecord(
        cve_id="CVE-FAKE-001", vendor="TestVendor", product="ProductA",
        vuln_name="Fake Vuln 1", date_added=datetime.date(2026, 10, 1),
        due_date=datetime.date(2026, 10, 10),  # OVERDUE by 8 days
        short_description="...", required_action="...",
        ransomware_use="Known", notes="", cwes=["CWE-79"],
        age_days=17, days_until_due=-8, is_overdue=True
    ),
    FakeRecord(
        cve_id="CVE-FAKE-002", vendor="TestVendor", product="ProductB",
        date_added=datetime.date(2026, 10, 5),
        due_date=datetime.date(2026, 10, 15),  # OVERDUE by 3 days
        vuln_name="Fake Vuln 2", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=["CWE-89"],
        age_days=13, days_until_due=-3, is_overdue=True
    ),
    FakeRecord(
        cve_id="CVE-FAKE-003", vendor="AnotherVendor", product="ProductA",
        date_added=datetime.date(2026, 10, 10),
        due_date=datetime.date(2026, 10, 20),  # Due in 2 days (due-soon)
        vuln_name="Fake Vuln 3", short_description="...",
        required_action="...", ransomware_use="Known", notes="",
        cwes=["CWE-22"],
        age_days=8, days_until_due=2, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-004", vendor="AnotherVendor", product="ProductC",
        date_added=datetime.date(2026, 10, 12),
        due_date=datetime.date(2026, 10, 25),  # Due in 7 days (due-soon)
        vuln_name="Fake Vuln 4", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=["CWE-787"],
        age_days=6, days_until_due=7, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-005", vendor="BigCorp", product="ProductD",
        date_added=datetime.date(2026, 9, 1),
        due_date=datetime.date(2026, 11, 18),  # Due in 31 days (not yet due)
        vuln_name="Fake Vuln 5", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=["CWE-416"],
        age_days=47, days_until_due=31, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-006", vendor="BigCorp", product="ProductD",
        date_added=datetime.date(2026, 8, 1),
        due_date=datetime.date(2026, 12, 1),   # Due in 44 days (not yet due)
        vuln_name="Fake Vuln 6", short_description="...",
        required_action="...", ransomware_use="Known", notes="",
        cwes=["CWE-119"],
        age_days=78, days_until_due=44, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-007", vendor="BigCorp", product="ProductE",
        date_added=datetime.date(2026, 7, 15),
        due_date=None,                          # NO due date
        vuln_name="Fake Vuln 7", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=[],
        age_days=95, days_until_due=None, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-008", vendor="SmallCo", product="ProductF",
        date_added=datetime.date(2026, 6, 1),
        due_date=None,                          # NO due date
        vuln_name="Fake Vuln 8", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=["CWE-20"],
        age_days=139, days_until_due=None, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-009", vendor="TestVendor", product="ProductA",
        date_added=datetime.date(2026, 10, 16),
        due_date=datetime.date(2026, 10, 19),  # Due in 1 day (due-soon)
        vuln_name="Fake Vuln 9", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=["CWE-79"],
        age_days=2, days_until_due=1, is_overdue=False
    ),
    FakeRecord(
        cve_id="CVE-FAKE-010", vendor="SmallCo", product="ProductG",
        date_added=None,                        # MISSING date_added
        due_date=datetime.date(2026, 10, 25),
        vuln_name="Fake Vuln 10", short_description="...",
        required_action="...", ransomware_use="Unknown", notes="",
        cwes=[],
        age_days=None, days_until_due=7, is_overdue=False
    ),
]

FAKE_CATALOG_INFO = {
    "title": "FAKE Catalog for Testing",
    "catalog_version": "TEST-1.0",
    "date_released": "2026-10-18T00:00:00Z",
    "total_count": 10,
    "download_date": "2026-10-18",
    "reference_date": "2026-10-18",
}
