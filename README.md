# 🛡️ CISA KEV Prioritization Dashboard

> **Deterministic, auditable vulnerability prioritization for CISA's Known Exploited Vulnerabilities catalog.**

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.38%2B-FF4B4B?logo=streamlit&logoColor=white)
![CISA KEV](https://img.shields.io/badge/CISA-KEV%20Catalog-0071BC)

---

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Run the Dashboard](#-run-the-dashboard)
- [CLI Examples](#-cli-examples)
- [Project Structure](#-project-structure)
- [Prioritization Policy](#-prioritization-policy)
- [Data Quality & Interpretation](#-data-quality--interpretation)
- [Testing & Verification](#-testing--verification)
- [Team Credits](#-team-credits)
- [Scope & Safety Boundary](#-scope--safety-boundary)
- [License](#-license)

---

## Overview

A reproducible command-line and interactive web dashboard for analyzing CISA's
[Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog. It reads a frozen local catalog snapshot and creates a prioritized
remediation worklist, a provenance report, and four analytical charts.

This project is **defensive catalog analysis only** — it does not scan systems,
exploit vulnerabilities, or contact remote services during normal use.

| Item | Value |
| --- | --- |
| Source | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Bundled snapshot | `data/known_exploited_vulnerabilities_2026-11-04.json` |
| Catalog version | `2026.11.03` |
| Download date | `2026-11-04` |
| Frozen reference date | `2026-11-04` |
| Records in snapshot | 1,767 |

<details>
<summary>Snapshot Integrity (SHA-256)</summary>

```text
b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d
```

</details>

---

## ✨ Features

- 🔍 **Parses** the local KEV JSON catalog into `VulnerabilityRecord` objects
- ✅ **Validates** required fields, dates, malformed rows, and duplicate CVE IDs — retaining damaged rows for transparent reporting
- 📅 **Calculates** catalog age, days until due, and four deadline states
- 🔎 **Filters** by vendor, product, ransomware-use value, deadline state, and inclusive `date_added` range (AND logic)
- 📤 **Exports** an overdue-first CSV worklist with documented, deterministic sorting
- 📊 **Produces** vendor/product summaries, a text report, and four PNG charts
- 🌐 **Interactive Streamlit Dashboard** with dark cybersecurity theme, live CISA feed toggle, and one-click exports
- 🧪 **Automated tests** and a repeatable 30-record date-calculation verification worksheet

---

## 🚀 Quick Start

### Prerequisites

- Python **3.11** or later
- pip (included with Python)

### Installation

```bash
# Clone the repository
git clone https://github.com/cunoob03/kev-dashboard.git
cd kev-dashboard

# Create and activate virtual environment
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Install dependencies
python -m pip install -r requirements.txt
```

> **Note:** Charts use Matplotlib's headless Agg backend. On hosts with a
> read-only home directory, configure writable caches before running:
> ```bash
> export MPLCONFIGDIR="$PWD/.cache/matplotlib"
> export XDG_CACHE_HOME="$PWD/.cache"
> ```

---

## 🖥️ Run the Dashboard

### Interactive Web Application (Streamlit Cyber-HUD)

```bash
streamlit run app.py
```

The web application delivers an authentic **Cyber-HUD** defensive interface matching the team's presentation deck (*Black Sci Fi Computer Technology Presentation*):

- **Quick-Triage Action Bar** — 1-click presets for immediate operational triage:
  - `[ ALL VULNERABILITIES ]` — Complete catalog reset
  - `[ URGENT REMEDIATION ]` — Breached federal compliance deadlines (Overdue)
  - `[ RANSOMWARE CAMPAIGNS ]` — Documented ransomware syndicate weaponization
  - `[ MAJOR TECH PLATFORMS ]` — Enterprise tier platforms (Microsoft, Apple, Cisco, Google, Adobe)
- **Executive Risk Explainer Card** — Translates technical compliance metrics into plain English business context under CISA Binding Operational Directive (BOD) 22-01
- **Cleaned Control Architecture** — High-level search and filters visible on load, with deep date-math dials organized in an expandable `[ ADVANCED AUDIT & DATE CONTROLS ]` drawer
- **Chamfered Cyber Frames** — Cut-corner geometric styling (`clip-path`) with crisp high-contrast borders and telemetry bracket notation (`[SYS.ACTIVE]`, `[MANDATE: OVERDUE]`, `[THREAT: RANSOMWARE]`, `[STATUS: VERIFIED]`, `[LIVE FEED]`)
- **Dual-Mode Ingestion** — Frozen snapshot by default for 100% reproducible grading, with optional live CISA feed sync
- **Visual Analytics** — 150 DPI Cyber-HUD Matplotlib telemetry charts with `#070A0F` background, crisp white spines, and educational *"Counts ≠ Risk"* disclosures
- **CVE Inspector** — Deep telemetry inspection of CISA binding remediation mandates, advisories, and CWE classifications
- **One-Click Export** — Download auditable prioritized worklists as CSV (with provenance header) or JSON

### Command-Line Interface

```bash
python -m src.dashboard
```

The command prints the report and creates these files in `outputs/`:

| Output | Purpose |
| --- | --- |
| `dashboard_report_2026-11-04.txt` | Provenance, filters, statistics, data quality, rankings, rules, and limitations |
| `prioritized_worklist_2026-11-04.csv` | Selected records in transparent remediation order |
| `plot_top_vendors.png` | Top vendors by catalog presence |
| `plot_due_status.png` | Overdue, due-soon, and not-yet-due counts |
| `plot_monthly_trend.png` | Catalog additions per month, including zero-count months |
| `plot_ransomware_by_vendor.png` | Known versus Unknown ransomware-use values for top vendors |

---

## 💻 CLI Examples

```bash
# Exact, case-insensitive vendor or product filters
python -m src.dashboard --vendor Microsoft --output-dir outputs/microsoft
python -m src.dashboard --product Windows --output-dir outputs/windows

# Combine filters with AND logic
python -m src.dashboard --product Windows --ransomware Known \
  --due-status overdue --output-dir outputs/windows-overdue

# Inclusive date_added range
python -m src.dashboard --start-date 2026-01-01 --end-date 2026-11-04 \
  --output-dir outputs/recent

# Recalculate with a different reference date
python -m src.dashboard --reference-date 2026-10-20 --output-dir outputs/2026-10-20

# Select records without a usable catalog due date
python -m src.dashboard --due-status no_due_date --output-dir outputs/missing-dates

# Full help
python -m src.dashboard --help
```

To analyze another local JSON file, pass `--catalog path/to/catalog.json`. Use
`--download-date YYYY-MM-DD` only when that provenance is known; otherwise the
report deliberately shows `Unknown` rather than guessing from file metadata.

---

## 📁 Project Structure

```text
kev-dashboard/
├── .streamlit/
│   └── config.toml          # Streamlit dark theme configuration
├── data/
│   └── known_exploited_vulnerabilities_2026-11-04.json
├── docs/
│   ├── interface_contract.md
│   ├── prioritization_rules.md
│   ├── presentation_playbook.md
│   ├── validation.md
│   └── team_handoff_*.txt
├── outputs/                  # Generated reports, worklists, plots, verification
├── src/
│   ├── __init__.py
│   ├── config.py             # Shared settings (dates, paths, thresholds)
│   ├── constants.py          # Output names and CSV column definitions
│   ├── counters.py           # Dictionary tallies and NumPy summaries
│   ├── dashboard.py          # CLI report generator
│   ├── export.py             # CSV export with provenance header
│   ├── filters.py            # Non-mutating record filters
│   ├── models.py             # VulnerabilityRecord data model
│   ├── parser.py             # JSON catalog parser and validator
│   ├── plots.py              # Four headless Matplotlib charts
│   ├── prioritizer.py        # Deterministic priority ordering
│   ├── sample_check.py       # Reproducible sample for manual review
│   ├── sampling.py           # Shared source-row sampling logic
│   ├── test_data.py          # Fake records for test suite
│   └── verification.py       # Date-calculation verification worksheet
├── tests/
│   ├── test_parser.py        # Parser, date math, and validation tests
│   └── test_dashboard.py     # Filters, worklist, counters, and integration tests
├── app.py                    # Streamlit interactive web dashboard
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 📐 Prioritization Policy

The worklist uses **no invented severity, CVSS, or organization-specific risk
score**. Its ordering is intentionally simple and auditable:

1. **Overdue records first**, with the most overdue deadline first
2. **Other records with a valid deadline next**, earliest due date first
3. **Records without a usable due date last**
4. **Ties**: oldest `date_added` first; fully tied records retain source order

With the default configuration, **due soon** means from today through 14 days
ahead, inclusive. Due today is due soon, not overdue. Update `DUE_SOON_DAYS` in
`src/config.py` only when the team agrees to change this project-wide policy.

See [the full prioritization rules](docs/prioritization_rules.md).

---

## 🔬 Data Quality & Interpretation

The dashboard checks data quality against the **full catalog before filtering**,
so a filter cannot hide malformed or duplicate source records. Missing or invalid
values become `None`, are retained in the report, and appear in explicit
missing-value buckets where appropriate.

- A vendor or product count measures **catalog presence**, not vendor security or an organization's exposure
- `Unknown` ransomware use means **unconfirmed** — not confirmed absence
- `Overdue` describes CISA's catalog deadline; it does not prove a particular organization has not remediated the issue
- Monthly additions show **catalog addition dates**, not first-exploitation dates
- The bundled catalog supplies no numeric severity score, so this project does not invent one

---

## 🧪 Testing & Verification

```bash
# Run full test suite
python -m unittest discover -s tests -v

# Print reproducible sample for manual review
python -m src.sample_check

# Generate verification worksheet
python -m src.verification
```

The automated suite covers parser validation, missing values, duplicate CVEs,
leap days, deadline boundaries, sorting stability, CSV quoting, empty outputs,
filtering, reference-date overrides, and the full frozen catalog. The sample
tools consistently select 30 distinct source rows using seed 42 and create:

- `outputs/verification_sample_2026-11-04.csv`
- `outputs/verification_math_2026-11-04.md`

See [validation notes](docs/validation.md) and
[interface contract](docs/interface_contract.md) for details.

---

## 🌿 Git Branches & Versions

| Branch | Release | Description |
| --- | --- | --- |
| `main` | **v3.0** | Production release featuring the authentic Cyber-HUD interface, quick-triage bar, and executive explainer |
| `v3.0-cyber-hud` | **v3.0-dev** | Feature branch for the Cyber-HUD UI modernization matching the Canva presentation deck |
| `v2.0-dark` | **v2.0** | Preserved release with the initial dark cybersecurity theme (`5e44114`) |
| `v1.0-light` | **v1.0** | Baseline release with crisp light theme optimized for classroom projection |

---

## 👥 Team Credits

| Contributor | Email | Responsibilities |
| --- | --- | --- |
| **Duy** | cunoob02@gmail.com | Dashboard & Prioritization |
| **Khoa Anh** | anhkhoa2052006@gmail.com | Parser & Date Logic |
| **phanharany** | phanharany@gmail.com | Catalog Setup & Version Management |
| **Phucxo1xx** | 87871427+Phucxo1xx@users.noreply.github.com | Validation & Documentation |

For teammate ownership and maintenance notes, see:
- [Dashboard and prioritization handoff](docs/team_handoff_duy_dashboard_prioritization.txt)
- [Parser and date-logic handoff](docs/team_handoff_khoa_parser_date_logic.txt)

---

## 🔒 Scope & Safety Boundary

This project is a **defensive analysis tool** for an authoritative public catalog.
It performs no exploit development, target scanning, or remote security testing.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
