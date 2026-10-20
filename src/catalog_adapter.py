"""Standalone JSON adapter; teammates can pass their own record objects instead.

The dashboard accepts any object with the documented attributes. This adapter
keeps the standalone CLI usable without depending on a future parser module.
"""

import json
from dataclasses import dataclass
from datetime import date

from .constants import DEFAULT_REFERENCE_DATE


@dataclass(frozen=True)
class KEVRecord:
    cve_id: str
    vendor: str
    product: str
    vuln_name: str
    date_added: date | None
    due_date: date | None
    short_description: str
    required_action: str
    ransomware_use: str
    notes: str
    cwes: list[str]
    age_days: int | None
    days_until_due: int | None
    is_overdue: bool


def records_at_reference_date(records, reference_date):
    """Copy contract-compatible objects and recalculate dates without mutation."""
    if type(reference_date) is not date:
        raise ValueError("reference_date must be a datetime.date")
    result = []
    for record in records:
        days = (
            (record.due_date - reference_date).days
            if record.due_date is not None else None
        )
        fields = {
            name: getattr(record, name)
            for name in KEVRecord.__dataclass_fields__
        }
        fields.update(
            cwes=list(record.cwes),
            age_days=(
                (reference_date - record.date_added).days
                if record.date_added is not None else None
            ),
            days_until_due=days,
            is_overdue=days is not None and days < 0,
        )
        result.append(KEVRecord(**fields))
    return result


def _parse_date(value, cve_id, field):
    if value is None or value == "":
        return None
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError("expected YYYY-MM-DD")
        return parsed
    except (TypeError, ValueError) as error:
        raise ValueError(f"{cve_id}: invalid {field}: {value!r}") from error


def load_catalog(path, reference_date=DEFAULT_REFERENCE_DATE, download_date=None):
    """Return (records, metadata); reject malformed catalogs with useful errors."""
    with open(path, encoding="utf-8") as stream:
        catalog = json.load(stream)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("Catalog must contain a vulnerabilities list")
    rows = catalog["vulnerabilities"]
    if catalog.get("count") != len(rows):
        raise ValueError("Catalog count does not match the number of records")
    records = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("cveID"), str) or not row["cveID"]:
            raise ValueError(f"Record {index + 1} must have a nonempty cveID")
        cve_id = row["cveID"]
        names = {
            "vendor": "vendorProject", "product": "product",
            "vuln_name": "vulnerabilityName", "short_description": "shortDescription",
            "required_action": "requiredAction", "ransomware_use": "knownRansomwareCampaignUse",
            "notes": "notes",
        }
        values = {name: row.get(field, "") for name, field in names.items()}
        if any(not isinstance(value, str) for value in values.values()):
            raise ValueError(f"{cve_id}: text fields must be strings")
        cwes = row.get("cwes", [])
        if not isinstance(cwes, list) or any(not isinstance(cwe, str) for cwe in cwes):
            raise ValueError(f"{cve_id}: cwes must be a list of strings")
        records.append(KEVRecord(
            cve_id=cve_id, **values,
            date_added=_parse_date(row.get("dateAdded"), cve_id, "dateAdded"),
            due_date=_parse_date(row.get("dueDate"), cve_id, "dueDate"),
            cwes=list(cwes), age_days=None, days_until_due=None, is_overdue=False,
        ))
    metadata = {
        "title": catalog.get("title", "KEV catalog"),
        "catalog_version": catalog.get("catalogVersion", "Unknown"),
        "date_released": catalog.get("dateReleased", "Unknown"),
        "total_count": len(records),
        "download_date": str(download_date) if download_date else "Unknown",
        "reference_date": reference_date.isoformat(),
    }
    return records_at_reference_date(records, reference_date), metadata
