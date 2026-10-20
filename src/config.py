"""Shared settings for the parser and date calculations.

The dashboard currently has older settings in constants.py. Its owner needs
to migrate to this module when integrating the new parser interface.
"""

from datetime import date
from pathlib import Path

# Use the frozen project date, never today's date automatically.
DEFAULT_REFERENCE_DATE = date(2026, 10, 18)

# Due today through this many days ahead counts as "due_soon".
DUE_SOON_DAYS = 14

# Start from this file's location, so the path does not depend on the terminal.
CATALOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "known_exploited_vulnerabilities_2026-10-18.json"
)

# Supplied by the project owner; this date is NOT a field in the JSON.
CATALOG_DOWNLOAD_DATE = date(2026, 10, 18)
