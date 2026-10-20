"""Non-mutating filters for objects implementing the KEV record contract."""


def filter_by_vendor(records, vendor_name):
    """Match a complete vendor name, ignoring case."""
    return [record for record in records if record.vendor.casefold() == vendor_name.casefold()]


def filter_by_product(records, product_name):
    """Match a complete product name, ignoring case."""
    return [record for record in records if record.product.casefold() == product_name.casefold()]


def filter_by_ransomware(records, ransomware_value):
    """Unknown means unconfirmed ransomware use, not confirmed absence."""
    value = ransomware_value.casefold()
    if value not in {"known", "unknown"}:
        raise ValueError("ransomware_value must be Known or Unknown")
    return [record for record in records if record.ransomware_use.casefold() == value]


def filter_by_due_status(records, status):
    """Exclude undated records; today through day seven is due soon."""
    checks = {
        "overdue": lambda days: days < 0,
        "due_soon": lambda days: 0 <= days <= 7,
        "not_yet_due": lambda days: days > 7,
    }
    if status not in checks:
        raise ValueError("status must be overdue, due_soon, or not_yet_due")
    return [
        record for record in records
        if record.days_until_due is not None and checks[status](record.days_until_due)
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
