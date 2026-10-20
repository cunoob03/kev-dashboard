"""
Fake KEV records for testing dashboard code.
10 records with known, hand-calculated values.
"""
import datetime

from .models import VulnerabilityRecord
from . import config

FAKE_RECORDS = [
    VulnerabilityRecord(
        cve_id="CVE-FAKE-001", vendor_project="TestVendor", product="ProductA",
        vulnerability_name="Fake Vuln 1", date_added=datetime.date(2026, 10, 1),
        due_date=datetime.date(2026, 10, 10),  # OVERDUE by 8 days
        short_description="...", required_action="...",
        known_ransomware_campaign_use="Known", notes=None, cwes=["CWE-79"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-002", vendor_project="TestVendor", product="ProductB",
        date_added=datetime.date(2026, 10, 5),
        due_date=datetime.date(2026, 10, 15),  # OVERDUE by 3 days
        vulnerability_name="Fake Vuln 2", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=["CWE-89"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-003", vendor_project="AnotherVendor", product="ProductA",
        date_added=datetime.date(2026, 10, 10),
        due_date=datetime.date(2026, 10, 20),  # Due in 2 days (due-soon)
        vulnerability_name="Fake Vuln 3", short_description="...",
        required_action="...", known_ransomware_campaign_use="Known", notes=None,
        cwes=["CWE-22"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-004", vendor_project="AnotherVendor", product="ProductC",
        date_added=datetime.date(2026, 10, 12),
        due_date=datetime.date(2026, 10, 25),  # Due in 7 days (due-soon)
        vulnerability_name="Fake Vuln 4", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=["CWE-787"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-005", vendor_project="BigCorp", product="ProductD",
        date_added=datetime.date(2026, 9, 1),
        due_date=datetime.date(2026, 11, 18),  # Due in 31 days (not yet due)
        vulnerability_name="Fake Vuln 5", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=["CWE-416"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-006", vendor_project="BigCorp", product="ProductD",
        date_added=datetime.date(2026, 8, 1),
        due_date=datetime.date(2026, 12, 1),   # Due in 44 days (not yet due)
        vulnerability_name="Fake Vuln 6", short_description="...",
        required_action="...", known_ransomware_campaign_use="Known", notes=None,
        cwes=["CWE-119"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-007", vendor_project="BigCorp", product="ProductE",
        date_added=datetime.date(2026, 7, 15),
        due_date=None,                          # NO due date
        vulnerability_name="Fake Vuln 7", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=[],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-008", vendor_project="SmallCo", product="ProductF",
        date_added=datetime.date(2026, 6, 1),
        due_date=None,                          # NO due date
        vulnerability_name="Fake Vuln 8", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=["CWE-20"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-009", vendor_project="TestVendor", product="ProductA",
        date_added=datetime.date(2026, 10, 16),
        due_date=datetime.date(2026, 10, 19),  # Due in 1 day (due-soon)
        vulnerability_name="Fake Vuln 9", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=["CWE-79"],
    ),
    VulnerabilityRecord(
        cve_id="CVE-FAKE-010", vendor_project="SmallCo", product="ProductG",
        date_added=None,                        # MISSING date_added
        due_date=datetime.date(2026, 10, 25),
        vulnerability_name="Fake Vuln 10", short_description="...",
        required_action="...", known_ransomware_campaign_use="Unknown", notes=None,
        cwes=[],
    ),
]

FAKE_CATALOG_INFO = {
    "title": "FAKE Catalog for Testing",
    "catalog_version": "TEST-1.0",
    "date_released": "2026-10-18T00:00:00Z",
    "record_count": 10,
    "download_date": "2026-10-18",
    "reference_date": config.DEFAULT_REFERENCE_DATE.isoformat(),
}
