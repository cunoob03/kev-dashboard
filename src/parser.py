"""Read the frozen JSON using only Python's standard library.

load_catalog returns (metadata, records), in that order. Bad record values
become None; records and duplicate CVE IDs are retained for review.
File/header problems are in metadata["file_issues"]. Record problems are
available through find_data_quality_issues(records).
"""

import json
import re
from datetime import date
from pathlib import Path

from . import config
from .models import VulnerabilityRecord


def parse_date(text):
    """Read YYYY-MM-DD as a date; return None for missing or invalid input."""
    if not isinstance(text, str):
        return None

    text = text.strip()
    if not text:
        return None

    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        return None

    # Python also accepts some other ISO formats. Our contract uses YYYY-MM-DD.
    if parsed.isoformat() != text:
        return None
    return parsed


def _read_text(row, field_name, problems):
    """Read nonempty text; report the wrong type instead of converting it."""
    value = row.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        problems.append(field_name + " must be text.")
        return None
    if not value.strip():
        return None
    # Preserve meaningful source text, including punctuation and spacing.
    return value


def _read_date(row, field_name, problems):
    """Distinguish an invalid date from a missing date for quality reporting."""
    value = row.get(field_name)
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None

    parsed = parse_date(value)
    if parsed is None:
        problems.append(field_name + " must be a valid date in YYYY-MM-DD format.")
    return parsed


def _read_cwes(row, problems):
    """A CWE value must be a list of nonempty text labels; [] is valid."""
    values = row.get("cwes")
    if values is None:
        return None
    if not isinstance(values, list):
        problems.append("cwes must be a list of nonempty text labels.")
        return None

    for value in values:
        if not isinstance(value, str) or not value.strip():
            problems.append("cwes contains an invalid label.")
            return None
    return list(values)


def _parse_record(row):
    """Build one record, keeping even a malformed row for the quality report."""
    problems = []
    if not isinstance(row, dict):
        problems.append("Record must be a JSON object; retained with None fields.")
        row = {}

    record = VulnerabilityRecord(
        cve_id=_read_text(row, "cveID", problems),
        vendor_project=_read_text(row, "vendorProject", problems),
        product=_read_text(row, "product", problems),
        vulnerability_name=_read_text(row, "vulnerabilityName", problems),
        date_added=_read_date(row, "dateAdded", problems),
        short_description=_read_text(row, "shortDescription", problems),
        required_action=_read_text(row, "requiredAction", problems),
        due_date=_read_date(row, "dueDate", problems),
        known_ransomware_campaign_use=_read_text(row, "knownRansomwareCampaignUse", problems),
        forensic_triage=_read_text(row, "forensicTriage", problems),
        notes=_read_text(row, "notes", problems),
        cwes=_read_cwes(row, problems),
    )

    # A CVE identifier has a four-digit year and at least four sequence digits.
    if record.cve_id is not None:
        if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", record.cve_id) is None:
            problems.append("cveID must have the form CVE-YYYY-NNNN (at least four final digits).")
            record.cve_id = None

    # Preserve text fields such as forensicTriage; do not guess new value rules.
    record.validation_issues = problems
    return record


def load_catalog(path=config.CATALOG_PATH):
    """Return (metadata, list of VulnerabilityRecord), without discarding bad rows.

    Metadata includes source information plus file_issues. An unreadable file,
    invalid JSON, or missing vulnerabilities list returns an empty record list
    and an explicit file issue. This is a failed load, not a valid empty catalog.
    A count mismatch is reported, but the actual records are still parsed.

    Only the bundled catalog has a known project-supplied download date. Other
    files get download_date=None; filesystem modification time is not evidence
    of a download date.
    """
    path = Path(path)
    metadata = {
        "title": None,
        "catalog_version": None,
        "date_released": None,
        "record_count": 0,
        "declared_record_count": None,
        "file_name": path.name,
        "download_date": None,
        "file_issues": [],
    }
    if path.resolve() == config.CATALOG_PATH.resolve():
        metadata["download_date"] = config.CATALOG_DOWNLOAD_DATE.isoformat()

    try:
        with path.open("r", encoding="utf-8") as file:
            catalog = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        metadata["file_issues"].append("Could not read catalog: " + str(error))
        return metadata, []

    if not isinstance(catalog, dict):
        metadata["file_issues"].append("The top-level JSON must be an object.")
        return metadata, []

    file_issues = metadata["file_issues"]
    metadata["title"] = _read_text(catalog, "title", file_issues)
    metadata["catalog_version"] = _read_text(catalog, "catalogVersion", file_issues)
    metadata["date_released"] = _read_text(catalog, "dateReleased", file_issues)
    if metadata["catalog_version"] is None:
        file_issues.append("Catalog version is missing or invalid.")
    if metadata["date_released"] is None:
        file_issues.append("Catalog release date is missing or invalid.")

    declared_count = catalog.get("count")
    # bool is a separate type: True must not be mistaken for a count of 1.
    if type(declared_count) is int and declared_count >= 0:
        metadata["declared_record_count"] = declared_count
    else:
        file_issues.append("count must be a nonnegative integer.")

    rows = catalog.get("vulnerabilities")
    if not isinstance(rows, list):
        file_issues.append("vulnerabilities must be a list.")
        return metadata, []

    records = []
    for row in rows:
        records.append(_parse_record(row))

    metadata["record_count"] = len(records)
    if metadata["declared_record_count"] is not None:
        if metadata["declared_record_count"] != len(records):
            file_issues.append("Declared count does not match the actual record count.")
    return metadata, records


def find_data_quality_issues(records):
    """List unavailable required fields, invalid values, and duplicate CVE IDs.

    Record numbers start at 1 and match source order, even when cve_id is None.
    "Missing" means unavailable after parsing, including rejected invalid values.
    invalid_records explains why a supplied value was rejected.

    total_issues counts missing-field flags, invalid-value messages, and distinct
    duplicated IDs. An invalid date produces both an unavailable-date flag and
    an invalid-value message. affected_record_count counts distinct records,
    including every occurrence of a duplicate. Duplicates are never deleted.
    """
    issues = {
        "missing_cve_id": [],
        "missing_vendor_project": [],
        "missing_product": [],
        "missing_date_added": [],
        "missing_due_date": [],
        "invalid_records": [],
        "duplicate_cve_ids": {},
        "total_issues": 0,
        "affected_record_count": 0,
    }
    positions_by_cve = {}
    affected_records = set()

    for number, record in enumerate(records, start=1):
        reference = {"record_number": number, "cve_id": record.cve_id}
        fields = {
            "missing_cve_id": record.cve_id,
            "missing_vendor_project": record.vendor_project,
            "missing_product": record.product,
            "missing_date_added": record.date_added,
            "missing_due_date": record.due_date,
        }
        for category, value in fields.items():
            if value is None:
                issues[category].append(dict(reference))
                issues["total_issues"] += 1
                affected_records.add(number)

        if record.validation_issues:
            detail = dict(reference)
            detail["messages"] = list(record.validation_issues)
            issues["invalid_records"].append(detail)
            issues["total_issues"] += len(record.validation_issues)
            affected_records.add(number)

        if record.cve_id is not None:
            if record.cve_id not in positions_by_cve:
                positions_by_cve[record.cve_id] = []
            positions_by_cve[record.cve_id].append(number)

    for cve_id, positions in positions_by_cve.items():
        if len(positions) > 1:
            issues["duplicate_cve_ids"][cve_id] = positions
            issues["total_issues"] += 1
            for number in positions:
                affected_records.add(number)

    issues["affected_record_count"] = len(affected_records)
    return issues
