"""Non-mutating filters for the parser's VulnerabilityRecord objects."""

from . import config


def filter_by_vendor(records, vendor_name):
    """Match a complete vendor name, ignoring case."""
    return [
        record for record in records
        if record.vendor_project is not None
        and record.vendor_project.casefold() == vendor_name.casefold()
    ]


def filter_by_product(records, product_name):
    """Match a complete product name, ignoring case."""
    return [
        record for record in records
        if record.product is not None and record.product.casefold() == product_name.casefold()
    ]


def filter_by_ransomware(records, ransomware_value):
    """Unknown means unconfirmed ransomware use, not confirmed absence."""
    value = ransomware_value.casefold()
    if value not in {"known", "unknown"}:
        raise ValueError("ransomware_value must be Known or Unknown")
    return [
        record for record in records
        if record.known_ransomware_campaign_use is not None
        and record.known_ransomware_campaign_use.casefold() == value
    ]


def filter_by_due_status(records, status, reference_date=config.DEFAULT_REFERENCE_DATE):
    """Use the model's shared date rules, including a no_due_date selection."""
    if status not in {"overdue", "due_soon", "not_yet_due", "no_due_date"}:
        raise ValueError("status must be overdue, due_soon, not_yet_due, or no_due_date")
    return [
        record for record in records
        if record.due_status(reference_date) == status
    ]


def filter_by_date_range(records, start_date=None, end_date=None):
    """Filter date_added inclusively; exclude records without date_added."""
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("start_date must not be after end_date")
    return [
        record for record in records
        if record.date_added is not None
        and (start_date is None or record.date_added >= start_date)
        and (end_date is None or record.date_added <= end_date)
    ]
