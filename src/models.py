"""The twelve catalog fields and the date calculations for one record.

The parser validates incoming values before constructing this class. Dates
passed directly to the constructor must already be datetime.date or None.
"""

from . import config


class VulnerabilityRecord:
    """One vulnerability, using snake_case names for all twelve JSON fields."""

    def __init__(
        self,
        cve_id=None,
        vendor_project=None,
        product=None,
        vulnerability_name=None,
        date_added=None,
        short_description=None,
        required_action=None,
        due_date=None,
        known_ransomware_campaign_use=None,
        forensic_triage=None,
        notes=None,
        cwes=None,
    ):
        # Store the catalog values on this particular record.
        self.cve_id = cve_id
        self.vendor_project = vendor_project
        self.product = product
        self.vulnerability_name = vulnerability_name
        self.date_added = date_added
        self.short_description = short_description
        self.required_action = required_action
        self.due_date = due_date
        self.known_ransomware_campaign_use = known_ransomware_campaign_use
        self.forensic_triage = forensic_triage
        self.notes = notes

        # Copy the list so changes to the caller's list cannot change this one.
        if cwes is None:
            self.cwes = None
        else:
            self.cwes = list(cwes)

        # These messages are parser diagnostics, not an invented catalog field.
        # Every record gets its own list.
        self.validation_issues = []

    def age_in_days(self, reference_date=config.DEFAULT_REFERENCE_DATE):
        """Days since addition; None when date_added is unavailable.

        Negative ages are retained if the reference date precedes date_added.
        Changing the date does not reconstruct an earlier catalog snapshot.
        """
        if self.date_added is None:
            return None
        difference = reference_date - self.date_added
        return difference.days

    def days_until_due(self, reference_date=config.DEFAULT_REFERENCE_DATE):
        """Due date minus reference date: negative means overdue."""
        if self.due_date is None:
            return None
        difference = self.due_date - reference_date
        return difference.days

    def due_status(self, reference_date=config.DEFAULT_REFERENCE_DATE):
        """Return one of the four agreed status strings.

        Due today (zero days remaining) is due_soon, NOT overdue.
        The due-soon upper boundary is inclusive: 14 days with current settings.
        """
        remaining_days = self.days_until_due(reference_date)

        if remaining_days is None:
            return "no_due_date"
        if remaining_days < 0:
            return "overdue"
        if remaining_days <= config.DUE_SOON_DAYS:
            return "due_soon"
        return "not_yet_due"
