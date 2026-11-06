"""
CISA KEV Prioritization Dashboard & Tactical Remediation Hub
Authentic Cyber-HUD Interface for Defensive Vulnerability Prioritization & Audit.
Matches Team Canva Deck: "Black Sci Fi Computer Technology Presentation"
"""

import csv
import io
import json
import tempfile
from datetime import date, datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st

from src import config
from src.constants import PLOT_FILENAMES, WORKLIST_CSV_COLUMNS
from src.counters import count_by_product, count_by_vendor, count_summary_stats
from src.export import export_worklist_csv
from src.filters import (
    filter_by_date_range, filter_by_due_status, filter_by_product,
    filter_by_ransomware, filter_by_vendor,
)
from src.models import VulnerabilityRecord
from src.parser import find_data_quality_issues, load_catalog, parse_date
from src.plots import (
    plot_due_status, plot_monthly_trend, plot_ransomware_by_vendor, plot_top_vendors,
)
from src.prioritizer import PrioritizedWorklist

# -- Cyber-HUD Telemetry Palette ----------------------------------------------
COLOR_HUD_BG = "#070A0F"          # Pure deep cybernetic carbon
COLOR_HUD_PANEL = "#0B0F17"       # Chamfered panel / surface
COLOR_HUD_TEXT = "#FFFFFF"        # Pure high-contrast white
COLOR_HUD_MUTED = "#94A3B8"       # Cold telemetry silver
COLOR_HUD_CYAN = "#38BDF8"        # Electric cyan telemetry accent
COLOR_HUD_RED = "#EF4444"         # Urgent mandate overdue crimson
COLOR_HUD_AMBER = "#F59E0B"       # Approaching deadline warning
COLOR_HUD_GREEN = "#10B981"       # Verified safe / passed telemetry

# -----------------------------------------------------------------------------
# Streamlit Page Config
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CISA KEV // DEFENSIVE HUD",
    page_icon=":material/radar:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -- Cyber-HUD Global Theme CSS ------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Global Typography & Font Smoothing */
    html, body, [class*="st-"], .stApp {
        font-family: 'Montserrat', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        color: #F1F5F9;
        -webkit-font-smoothing: antialiased;
    }

    /* Sci-Fi Deep Cybernetic Carbon Grid */
    .stApp {
        background-color: #070A0F;
        background-image: 
            linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
            radial-gradient(circle at 50% 0%, rgba(56, 189, 248, 0.07) 0%, transparent 65%);
        background-size: 32px 32px, 32px 32px, 100% 100%;
        background-position: 0 0, 0 0, 0 0;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #070A0F !important;
        border-right: 1.5px solid rgba(255, 255, 255, 0.15);
        background-image: 
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
        background-size: 24px 24px;
    }
    section[data-testid="stSidebar"] > div {
        background-color: transparent !important;
    }

    /* Chamfered Card Base Frame */
    .hud-card {
        background: #0B0F17;
        border: 1.5px solid rgba(255, 255, 255, 0.28);
        clip-path: polygon(14px 0, 100% 0, 100% calc(100% - 14px), calc(100% - 14px) 100%, 0 100%, 0 14px);
        padding: 16px 20px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6), inset 0 0 15px rgba(56, 189, 248, 0.03);
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .hud-card:hover {
        border-color: rgba(255, 255, 255, 0.6);
        box-shadow: 0 0 25px rgba(56, 189, 248, 0.15), inset 0 0 16px rgba(56, 189, 248, 0.06);
    }
    .hud-card-accent-red {
        border-left: 3px solid #EF4444;
    }
    .hud-card-accent-cyan {
        border-left: 3px solid #38BDF8;
    }
    .hud-card-accent-amber {
        border-left: 3px solid #F59E0B;
    }
    .hud-card-accent-green {
        border-left: 3px solid #10B981;
    }

    /* Chamfered KPI Metric Card */
    .hud-kpi-card {
        background: #0B0F17;
        border: 1.5px solid rgba(255, 255, 255, 0.24);
        clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
        padding: 14px 18px;
        position: relative;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.5);
        transition: all 0.2s ease;
        margin-bottom: 8px;
    }
    .hud-kpi-card:hover {
        border-color: rgba(56, 189, 248, 0.7);
        box-shadow: 0 0 20px rgba(56, 189, 248, 0.2);
    }
    .hud-kpi-header {
        font-size: 0.72rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        font-weight: 700;
        color: #94A3B8;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }
    .hud-kpi-value {
        font-size: 1.85rem;
        font-weight: 800;
        color: #FFFFFF;
        line-height: 1.1;
        letter-spacing: -0.02em;
        font-family: 'Montserrat', sans-serif;
    }
    .hud-kpi-delta {
        font-size: 0.72rem;
        font-weight: 600;
        color: #64748B;
        font-family: 'JetBrains Mono', monospace;
        margin-top: 6px;
    }

    /* Telemetry Brackets & Decals */
    .hud-tag {
        display: inline-block;
        padding: 2px 7px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        font-family: 'JetBrains Mono', monospace;
        text-transform: uppercase;
        border: 1px solid rgba(255, 255, 255, 0.2);
        background: rgba(255, 255, 255, 0.04);
    }
    .hud-tag-cyan {
        color: #38BDF8;
        border-color: rgba(56, 189, 248, 0.5);
        background: rgba(56, 189, 248, 0.1);
    }
    .hud-tag-red {
        color: #EF4444;
        border-color: rgba(239, 68, 68, 0.5);
        background: rgba(239, 68, 68, 0.12);
    }
    .hud-tag-amber {
        color: #F59E0B;
        border-color: rgba(245, 158, 11, 0.5);
        background: rgba(245, 158, 11, 0.12);
    }
    .hud-tag-green {
        color: #10B981;
        border-color: rgba(16, 185, 129, 0.5);
        background: rgba(16, 185, 129, 0.12);
    }
    .hud-slash {
        color: #38BDF8;
        font-weight: 800;
        margin-right: 4px;
    }

    /* Tabs - Cyber HUD Chamfered Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #070A0F;
        border-bottom: 1.5px solid rgba(255, 255, 255, 0.2);
        padding: 6px 0px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0B0F17;
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 0px;
        clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
        color: #94A3B8;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        padding: 10px 18px;
        transition: all 0.2s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        color: #FFFFFF;
        border-color: rgba(255, 255, 255, 0.5);
        background-color: rgba(56, 189, 248, 0.08);
    }
    .stTabs [aria-selected="true"] {
        color: #FFFFFF !important;
        background-color: #0E1624 !important;
        border: 1.5px solid #38BDF8 !important;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.25) !important;
    }

    /* Streamlit Buttons - Chamfered & High-Contrast */
    .stButton > button {
        border-radius: 0px;
        clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.05em;
        font-family: 'Montserrat', sans-serif;
        border: 1.5px solid rgba(255, 255, 255, 0.3);
        background-color: #0B0F17;
        color: #E2E8F0;
        padding: 8px 16px;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        border-color: #FFFFFF;
        color: #FFFFFF;
        background-color: rgba(56, 189, 248, 0.12);
        box-shadow: 0 0 16px rgba(56, 189, 248, 0.25);
    }
    .stButton > button[kind="primary"], .stButton > button:active {
        border-color: #38BDF8 !important;
        background-color: #0A2540 !important;
        color: #FFFFFF !important;
        box-shadow: 0 0 18px rgba(56, 189, 248, 0.45) !important;
    }

    /* Form Inputs & Selects */
    .stTextInput input, .stSelectbox [data-baseweb="select"], .stMultiSelect [data-baseweb="select"] {
        background-color: #0B0F17 !important;
        border: 1.5px solid rgba(255, 255, 255, 0.2) !important;
        border-radius: 0px !important;
        color: #FFFFFF !important;
    }
    .stSelectbox label, .stMultiSelect label, .stDateInput label, .stTextInput label, .stSlider label {
        color: #CBD5E1 !important;
        font-weight: 600 !important;
        font-size: 0.78rem !important;
        letter-spacing: 0.04em !important;
        text-transform: uppercase;
    }

    /* Expanders */
    div[data-testid="stExpander"] {
        border: 1.5px solid rgba(255, 255, 255, 0.18) !important;
        background-color: #080C14 !important;
        border-radius: 0px !important;
        margin-bottom: 12px;
    }
    .streamlit-expanderHeader {
        background-color: #0B0F17 !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.04em !important;
    }

    /* Dataframe styling */
    .stDataFrame {
        border: 1.5px solid rgba(255, 255, 255, 0.18);
        border-radius: 0px;
    }

    /* Dividers */
    hr {
        border-color: rgba(255, 255, 255, 0.12) !important;
    }

    /* Captions */
    .stCaption {
        color: #94A3B8 !important;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Montserrat', sans-serif !important;
        font-weight: 800 !important;
        color: #FFFFFF !important;
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #070A0F;
    }
    ::-webkit-scrollbar-thumb {
        background: #1E293B;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #38BDF8;
    }
</style>
""", unsafe_allow_html=True)

CISA_LIVE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# -----------------------------------------------------------------------------
# Data Loading & Caching
# -----------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def get_catalog_from_file(catalog_path: Path):
    """Load catalog from local JSON snapshot with caching."""
    return load_catalog(catalog_path)


def fetch_live_catalog():
    """Download the latest official CISA KEV JSON catalog."""
    response = requests.get(CISA_LIVE_URL, timeout=15)
    response.raise_for_status()
    data = response.json()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tmp:
        json.dump(data, tmp)
        tmp_path = Path(tmp.name)
    metadata, records = load_catalog(tmp_path)
    metadata["download_date"] = date.today().isoformat()
    return metadata, records


# -----------------------------------------------------------------------------
# App State Initialization
# -----------------------------------------------------------------------------
if "use_live_cisa" not in st.session_state:
    st.session_state.use_live_cisa = False
if "live_metadata" not in st.session_state:
    st.session_state.live_metadata = None
if "live_records" not in st.session_state:
    st.session_state.live_records = None

# Filter state
if "filter_vendors" not in st.session_state:
    st.session_state.filter_vendors = []
if "filter_product" not in st.session_state:
    st.session_state.filter_product = ""
if "filter_ransomware" not in st.session_state:
    st.session_state.filter_ransomware = "All"
if "filter_due_status" not in st.session_state:
    st.session_state.filter_due_status = "All"

# Resolve Active Catalog
if st.session_state.use_live_cisa and st.session_state.live_records:
    raw_metadata = st.session_state.live_metadata
    all_records = st.session_state.live_records
    catalog_source_label = "LIVE CISA FEED"
    catalog_source_tag = "[LIVE FEED]"
else:
    raw_metadata, all_records = get_catalog_from_file(config.CATALOG_PATH)
    catalog_source_label = f"FROZEN SNAPSHOT ({config.CATALOG_PATH.name})"
    catalog_source_tag = "[CATALOG: FROZEN]"

unique_vendors = sorted({r.vendor_project for r in all_records if r.vendor_project})
st.session_state.available_vendors = unique_vendors


# -----------------------------------------------------------------------------
# Quick-Triage Action Callbacks
# -----------------------------------------------------------------------------
def apply_triage_preset(preset: str):
    """Callback to apply one-click quick triage presets across the platform."""
    if preset == "ALL":
        st.session_state.filter_vendors = []
        st.session_state.filter_product = ""
        st.session_state.filter_ransomware = "All"
        st.session_state.filter_due_status = "All"
    elif preset == "URGENT":
        st.session_state.filter_vendors = []
        st.session_state.filter_product = ""
        st.session_state.filter_ransomware = "All"
        st.session_state.filter_due_status = "overdue"
    elif preset == "RANSOMWARE":
        st.session_state.filter_vendors = []
        st.session_state.filter_product = ""
        st.session_state.filter_ransomware = "Known"
        st.session_state.filter_due_status = "All"
    elif preset == "MAJOR_TECH":
        majors = ["Adobe", "Apple", "Cisco", "Google", "Microsoft"]
        avail = st.session_state.get("available_vendors", unique_vendors)
        st.session_state.filter_vendors = [v for v in majors if v in avail]
        st.session_state.filter_product = ""
        st.session_state.filter_ransomware = "All"
        st.session_state.filter_due_status = "All"


def detect_active_preset(catalog_vendors: list) -> str:
    """Identify which quick-triage preset matches the current filter settings."""
    v = set(st.session_state.get("filter_vendors", []))
    p = st.session_state.get("filter_product", "").strip()
    r = st.session_state.get("filter_ransomware", "All")
    d = st.session_state.get("filter_due_status", "All")

    if not v and not p and r == "All" and d == "All":
        return "ALL"
    if not v and not p and r == "All" and d == "overdue":
        return "URGENT"
    if not v and not p and r == "Known" and d == "All":
        return "RANSOMWARE"
    majors = set(m for m in ["Adobe", "Apple", "Cisco", "Google", "Microsoft"] if m in catalog_vendors)
    if v == majors and not p and r == "All" and d == "All":
        return "MAJOR_TECH"
    return "CUSTOM"


active_triage = detect_active_preset(unique_vendors)


# -----------------------------------------------------------------------------
# Sidebar: Provenance & Controls
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="margin-bottom: 12px;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #38BDF8; letter-spacing: 0.12em; text-transform: uppercase;">
            // TELEMETRY // SYSTEM 3.0
        </div>
        <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.01em; margin-top: 2px;">
            CISA KEV // HUD
        </div>
        <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 2px;">
            Defensive Triage &amp; Remediation Hub
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("**// DATA SOURCE FEED**")

    sync_col1, sync_col2 = st.columns([1.4, 1])
    with sync_col1:
        if st.session_state.use_live_cisa:
            st.markdown("<span class='hud-tag hud-tag-green'>[FEED: LIVE CISA]</span>", unsafe_allow_html=True)
        else:
            st.markdown("<span class='hud-tag hud-tag-cyan'>[CATALOG: FROZEN]</span>", unsafe_allow_html=True)

    with sync_col2:
        if not st.session_state.use_live_cisa:
            if st.button("[ FETCH LIVE ]", help="Download current live JSON feed from CISA.gov"):
                with st.spinner("Connecting to CISA..."):
                    try:
                        meta, recs = fetch_live_catalog()
                        st.session_state.live_metadata = meta
                        st.session_state.live_records = recs
                        st.session_state.use_live_cisa = True
                        st.rerun()
                    except Exception as e:
                        st.error(f"Live fetch error: {e}")
        else:
            if st.button("[ RESET FROZEN ]"):
                st.session_state.use_live_cisa = False
                st.rerun()

    st.markdown("---")
    st.markdown("**// PRIMARY FILTER CONTROLS**")

    # Simple Search & Quick Controls (Always Visible)
    selected_vendors = st.multiselect(
        "Vendor / Project",
        options=unique_vendors,
        key="filter_vendors",
        help="Filter to records matching specific vendors."
    )

    product_query = st.text_input(
        "Product Keyword",
        placeholder="e.g. Windows, IOS, Acrobat",
        key="filter_product",
        help="Case-insensitive substring search for affected products."
    )

    ransomware_filter = st.selectbox(
        "Ransomware Campaign Use",
        options=["All", "Known", "Unknown"],
        key="filter_ransomware",
        help="Filter by documented ransomware weaponization."
    )

    # Reference window temporary for label
    due_window_val = st.session_state.get("filter_due_window", config.DUE_SOON_DAYS)

    due_status_filter = st.selectbox(
        "Compliance Deadline Status",
        options=["All", "overdue", "due_soon", "not_yet_due", "no_due_date"],
        format_func=lambda s: {
            "All": "[ ALL DEADLINE STATUSES ]",
            "overdue": "[MANDATE: OVERDUE] (< 0 days)",
            "due_soon": f"[STATUS: DUE SOON] (0–{due_window_val} days)",
            "not_yet_due": f"[STATUS: NOT YET DUE] (> {due_window_val} days)",
            "no_due_date": "[NO DUE DATE LISTED]",
        }.get(s, s),
        key="filter_due_status",
        help="Filter by CISA remediation deadline compliance."
    )

    st.markdown("---")

    # Expandable Drawer for Deep Date-Math Dials
    with st.expander("[ ADVANCED AUDIT & DATE CONTROLS ]", expanded=False):
        st.caption("Deep date-math calibration for historical verification and audit baselines.")

        ref_date_input = st.date_input(
            "Audit Reference Date",
            value=st.session_state.get("filter_ref_date", config.DEFAULT_REFERENCE_DATE),
            help="Reference baseline against which age and compliance deadlines are evaluated.",
            key="filter_ref_date"
        )
        if isinstance(ref_date_input, datetime):
            reference_date = ref_date_input.date()
        else:
            reference_date = ref_date_input

        due_soon_window = st.slider(
            "Due-Soon Window (Days)",
            min_value=1,
            max_value=60,
            value=st.session_state.get("filter_due_window", config.DUE_SOON_DAYS),
            help="Calendar day threshold from reference date categorized as Due Soon.",
            key="filter_due_window"
        )

        st.markdown("**Catalog Date Added Boundaries**")
        date_col1, date_col2 = st.columns(2)
        with date_col1:
            start_date = st.date_input("From Date", value=st.session_state.get("filter_date_start", None), key="filter_date_start")
        with date_col2:
            end_date = st.date_input("To Date", value=st.session_state.get("filter_date_end", None), key="filter_date_end")

# Resolve reference date & window
if "reference_date" not in locals():
    ref_val = st.session_state.get("filter_ref_date", config.DEFAULT_REFERENCE_DATE)
    reference_date = ref_val.date() if isinstance(ref_val, datetime) else ref_val
if "due_soon_window" not in locals():
    due_soon_window = st.session_state.get("filter_due_window", config.DUE_SOON_DAYS)


# -----------------------------------------------------------------------------
# Data Filtering & Prioritization Pipeline
# -----------------------------------------------------------------------------
config.DUE_SOON_DAYS = due_soon_window
selected = list(all_records)
applied_filters = []

if selected_vendors:
    selected = [r for r in selected if r.vendor_project and r.vendor_project in selected_vendors]
    applied_filters.append(f"vendor in {selected_vendors}")

if product_query.strip():
    selected = filter_by_product(selected, product_query.strip())
    applied_filters.append(f"product = '{product_query.strip()}'")

if ransomware_filter != "All":
    selected = filter_by_ransomware(selected, ransomware_filter)
    applied_filters.append(f"ransomware = '{ransomware_filter}'")

if due_status_filter != "All":
    selected = filter_by_due_status(selected, due_status_filter, reference_date)
    applied_filters.append(f"due_status = '{due_status_filter}'")

if start_date or end_date:
    selected = filter_by_date_range(selected, start_date, end_date)
    applied_filters.append(f"date_added between {start_date or 'any'} and {end_date or 'any'}")

# Build Deterministic Prioritized Worklist Object
worklist_metadata = dict(raw_metadata)
worklist_metadata["reference_date"] = reference_date.isoformat()
worklist = PrioritizedWorklist(selected, worklist_metadata, applied_filters, reference_date=reference_date)
stats = worklist.summary_stats()
data_quality = find_data_quality_issues(all_records)


# -----------------------------------------------------------------------------
# Main Header & Provenance Status Bar
# -----------------------------------------------------------------------------
st.markdown("""
<div style="margin-bottom: 0.8rem;">
    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; color: #38BDF8; letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 4px;">
        // CYBER-HUD DEFENSIVE COMMAND INTERFACE // SYSTEM VERSION 3.0
    </div>
    <h1 style="font-size: 2.15rem; font-weight: 900; margin: 0; padding: 0; letter-spacing: -0.01em; color: #FFFFFF;">
        CISA KEV // PRIORITIZATION HUD
    </h1>
    <div style="font-size: 0.86rem; color: #94A3B8; margin-top: 4px; font-weight: 500;">
        Defensive Vulnerability Triage, Federal Remediation Tracking &amp; Forensic Catalog Audit
    </div>
</div>
""", unsafe_allow_html=True)

# Provenance Status Bar
st.markdown(f"""
<div class="hud-card" style="padding: 10px 18px; margin-bottom: 14px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; font-size: 0.76rem; font-family: 'JetBrains Mono', monospace;">
    <div><span class="hud-slash">//</span><strong>CATALOG:</strong> {raw_metadata.get('catalog_version', 'Unknown')}</div>
    <div><span class="hud-slash">//</span><strong>RELEASED:</strong> {raw_metadata.get('date_released', 'Unknown')[:10]}</div>
    <div><span class="hud-slash">//</span><strong>REFERENCE DATE:</strong> {reference_date.isoformat()}</div>
    <div><span class="hud-slash">//</span><strong>FEED STATUS:</strong> <span class="hud-tag {'hud-tag-green' if st.session_state.use_live_cisa else 'hud-tag-cyan'}">{catalog_source_tag}</span></div>
</div>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Quick-Triage Action Bar (One-Click Presets)
# -----------------------------------------------------------------------------
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 6px;">
    <span style="font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #CBD5E1; letter-spacing: 0.08em;">
        // QUICK-TRIAGE ACTION BAR
    </span>
    <span class="hud-tag hud-tag-cyan">[TELEMETRY: 1-CLICK DISPATCH]</span>
</div>
""", unsafe_allow_html=True)

triage_c1, triage_c2, triage_c3, triage_c4 = st.columns(4)

with triage_c1:
    st.button(
        "[ ALL VULNERABILITIES ]",
        use_container_width=True,
        type="primary" if active_triage == "ALL" else "secondary",
        on_click=apply_triage_preset,
        args=("ALL",),
        help="Reset filters to display the complete unconstrained catalog."
    )

with triage_c2:
    st.button(
        "[ URGENT REMEDIATION ]",
        use_container_width=True,
        type="primary" if active_triage == "URGENT" else "secondary",
        on_click=apply_triage_preset,
        args=("URGENT",),
        help="Isolate vulnerabilities that have breached mandatory federal remediation deadlines."
    )

with triage_c3:
    st.button(
        "[ RANSOMWARE CAMPAIGNS ]",
        use_container_width=True,
        type="primary" if active_triage == "RANSOMWARE" else "secondary",
        on_click=apply_triage_preset,
        args=("RANSOMWARE",),
        help="Isolate vulnerabilities with documented threat-actor weaponization in ransomware campaigns."
    )

with triage_c4:
    st.button(
        "[ MAJOR TECH PLATFORMS ]",
        use_container_width=True,
        type="primary" if active_triage == "MAJOR_TECH" else "secondary",
        on_click=apply_triage_preset,
        args=("MAJOR_TECH",),
        help="Filter to enterprise infrastructure vendors: Microsoft, Apple, Cisco, Google, Adobe."
    )


# -----------------------------------------------------------------------------
# Plain-English Risk Explainer Card (Executive Translation)
# -----------------------------------------------------------------------------
def get_risk_explainer_html(preset: str, stats_dict: dict, window_days: int) -> str:
    """Translate technical compliance metrics into plain English business context."""
    if preset == "URGENT":
        title_tag = "[TACTICAL FOCUS // OVERDUE MANDATES]"
        summary_body = (
            f"You are viewing <strong>{stats_dict['overdue_count']:,} overdue vulnerabilities</strong>. "
            "Under <strong>CISA Binding Operational Directive (BOD) 22-01</strong>, federal civilian executive agencies "
            "are legally required to remediate KEV vulnerabilities within specified calendar deadlines. "
            "These deadlines have now expired. In defensive operations, overdue vulnerabilities carry confirmed, active "
            "in-the-wild exploitation and represent highest immediate exposure to automated exploitation and lateral movement. "
            "Remediation teams must assign Priority 1 status to these records immediately."
        )
    elif preset == "RANSOMWARE":
        title_tag = "[TACTICAL FOCUS // RANSOMWARE OPERATIONS]"
        summary_body = (
            f"You are viewing <strong>{stats_dict['ransomware_known_count']:,} vulnerabilities with confirmed ransomware campaign weaponization</strong>. "
            "Threat syndicates leverage these specific weaknesses for initial breach access, credential exfiltration, and lateral "
            "privilege escalation prior to data extortion. Remediating these vulnerabilities eliminates documented ransomware entry "
            "points and protects business operational continuity."
        )
    elif preset == "MAJOR_TECH":
        title_tag = "[TACTICAL FOCUS // ENTERPRISE TIER PLATFORMS]"
        summary_body = (
            f"You are viewing <strong>{stats_dict['total']:,} vulnerabilities affecting major technology platforms</strong> "
            "(Microsoft, Apple, Cisco, Google, Adobe). While high catalog numbers reflect widespread enterprise adoption, transparent "
            "disclosure, and extensive vulnerability research rather than flawed engineering (<strong>'Counts ≠ Risk'</strong>), "
            "their ubiquity makes them prime targets for widespread intrusion campaigns. Coordinate deployment across identity and boundary systems."
        )
    else:
        title_tag = "[EXECUTIVE BRIEFING // BINDING DIRECTIVE COMPLIANCE]"
        summary_body = (
            f"Displaying <strong>{stats_dict['total']:,} vulnerabilities</strong> from the authoritative CISA KEV catalog. "
            "Unlike academic CVSS scores, every flaw in this catalog has <strong>confirmed, weaponized in-the-wild exploitation</strong>. "
            "Under federal directive BOD 22-01, remediation is tracked against auditable compliance deadlines: "
            f"<strong>{stats_dict['overdue_count']:,}</strong> have expired past their federal due date (Overdue), "
            f"<strong>{stats_dict['due_soon_count']:,}</strong> expire within {window_days} days (Due Soon), and "
            f"<strong>{stats_dict['ransomware_known_count']:,}</strong> are tied to ransomware operations. "
            "Defensive triage should address overdue items first."
        )

    return f"""
    <div class="hud-card hud-card-accent-cyan" style="margin-top: 10px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-weight: 800; font-size: 0.85rem; letter-spacing: 0.05em; color: #FFFFFF;">
                <span class="hud-slash">//</span>EXECUTIVE RISK TRANSLATION &amp; MANDATE DIRECTIVE
            </span>
            <span class="hud-tag hud-tag-cyan">{title_tag}</span>
        </div>
        <div style="font-size: 0.84rem; line-height: 1.6; color: #CBD5E1;">
            {summary_body}
        </div>
        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(255, 255, 255, 0.1); display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; color: #94A3B8;">
            <span><span class="hud-slash">//</span>STATUS: <strong style="color: #EF4444;">{stats_dict['overdue_count']:,} OVERDUE</strong></span>
            <span><span class="hud-slash">//</span>WINDOW: <strong style="color: #F59E0B;">{stats_dict['due_soon_count']:,} DUE SOON</strong></span>
            <span><span class="hud-slash">//</span>CAMPAIGNS: <strong style="color: #38BDF8;">{stats_dict['ransomware_known_count']:,} RANSOMWARE</strong></span>
            <span><span class="hud-slash">//</span>PRINCIPLE: <strong style="color: #10B981;">COUNTS ≠ RISK</strong></span>
        </div>
    </div>
    """

st.markdown(get_risk_explainer_html(active_triage, stats, due_soon_window), unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Key Metric Cards (KPI Telemetry)
# -----------------------------------------------------------------------------
kpi_c1, kpi_c2, kpi_c3, kpi_c4, kpi_c5 = st.columns(5)

with kpi_c1:
    st.markdown(f"""
    <div class="hud-kpi-card">
        <div class="hud-kpi-header">
            <span><span class="hud-slash">//</span>SELECTED SET</span>
            <span class="hud-tag hud-tag-cyan">[SYS.ACTIVE]</span>
        </div>
        <div class="hud-kpi-value">{stats['total']:,}</div>
        <div class="hud-kpi-delta">OF {len(all_records):,} TOTAL CATALOG</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_c2:
    st.markdown(f"""
    <div class="hud-kpi-card">
        <div class="hud-kpi-header">
            <span><span class="hud-slash">//</span>MANDATE OVERDUE</span>
            <span class="hud-tag hud-tag-red">[MANDATE: OVERDUE]</span>
        </div>
        <div class="hud-kpi-value" style="color: #EF4444;">{stats['overdue_count']:,}</div>
        <div class="hud-kpi-delta" style="color: #EF4444;">{"URGENT REMEDIATION REQ" if stats['overdue_count'] else "ZERO OVERDUE"}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_c3:
    st.markdown(f"""
    <div class="hud-kpi-card">
        <div class="hud-kpi-header">
            <span><span class="hud-slash">//</span>DUE SOON WINDOW</span>
            <span class="hud-tag hud-tag-amber">[STATUS: DUE SOON]</span>
        </div>
        <div class="hud-kpi-value" style="color: #F59E0B;">{stats['due_soon_count']:,}</div>
        <div class="hud-kpi-delta">0 TO {due_soon_window} CALENDAR DAYS</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_c4:
    st.markdown(f"""
    <div class="hud-kpi-card">
        <div class="hud-kpi-header">
            <span><span class="hud-slash">//</span>RANSOMWARE USE</span>
            <span class="hud-tag hud-tag-red">[THREAT: RANSOMWARE]</span>
        </div>
        <div class="hud-kpi-value">{stats['ransomware_known_count']:,}</div>
        <div class="hud-kpi-delta">CONFIRMED CAMPAIGN USE</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_c5:
    mean_age_str = f"{stats['mean_age_days']:.0f} d" if stats['mean_age_days'] is not None else "N/A"
    median_age_str = f"{stats['median_age_days']:.0f} d" if stats['median_age_days'] is not None else "N/A"
    st.markdown(f"""
    <div class="hud-kpi-card">
        <div class="hud-kpi-header">
            <span><span class="hud-slash">//</span>CATALOG AGE</span>
            <span class="hud-tag hud-tag-cyan">[TELEMETRY: AGE]</span>
        </div>
        <div class="hud-kpi-value">{median_age_str}</div>
        <div class="hud-kpi-delta">MEDIAN (MEAN: {mean_age_str})</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Matplotlib Cyber-HUD Theme Engine
# -----------------------------------------------------------------------------
def apply_cyber_hud_chart_style(fig, ax, title_text=""):
    """Apply authentic Cyber-HUD telemetry theme to Matplotlib figures."""
    fig.set_facecolor(COLOR_HUD_BG)
    ax.set_facecolor(COLOR_HUD_PANEL)

    # Crisp high-contrast spines
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines["bottom"].set_color("#FFFFFF")
    ax.spines["bottom"].set_linewidth(1.2)
    ax.spines["left"].set_color("#FFFFFF")
    ax.spines["left"].set_linewidth(1.2)

    # Crisp ticks and typography
    ax.tick_params(colors="#FFFFFF", which="both", labelsize=9)
    ax.xaxis.label.set_color("#CBD5E1")
    ax.yaxis.label.set_color("#CBD5E1")
    ax.xaxis.label.set_fontsize(9.5)
    ax.yaxis.label.set_fontsize(9.5)

    # Subtle dashed cyber grid
    ax.grid(axis="y", color="#FFFFFF", alpha=0.10, linewidth=0.6, linestyle="--")
    ax.set_axisbelow(True)

    if title_text:
        ax.set_title(
            f"// {title_text.upper()}",
            fontweight="bold",
            loc="left",
            color="#FFFFFF",
            fontsize=10.5,
            pad=10
        )


# -----------------------------------------------------------------------------
# Tabbed Cyber-HUD Navigation
# -----------------------------------------------------------------------------
tab_worklist, tab_charts, tab_inspector, tab_quality, tab_docs = st.tabs([
    "[01 // WORKLIST]",
    "[02 // VISUAL ANALYTICS]",
    "[03 // CVE INSPECTOR]",
    "[04 // AUDIT & QUALITY]",
    "[05 // POLICY & PLAYBOOK]"
])


# -----------------------------------------------------------------------------
# Tab 1: Prioritized Worklist (Remediation Hub)
# -----------------------------------------------------------------------------
with tab_worklist:
    st.markdown("""
    <div style="margin-bottom: 10px;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">
            // DETERMINISTIC REMEDIATION WORKLIST
        </div>
        <div style="font-size: 0.8rem; color: #94A3B8; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
            SORTING PROTOCOL: [1] Overdue flaws (furthest overdue first) &rarr; [2] Upcoming deadlines (earliest due first) &rarr; [3] Unspecified deadlines &rarr; [4] Oldest date added tie-break.
        </div>
    </div>
    """, unsafe_allow_html=True)

    prioritized_records = worklist.get_records()

    if not prioritized_records:
        st.markdown("""
        <div class="hud-card hud-card-accent-amber" style="padding: 14px 18px;">
            <span class="hud-tag hud-tag-amber">[QUERY.EMPTY]</span> No vulnerability records match the active filter criteria.
        </div>
        """, unsafe_allow_html=True)
    else:
        # Build DataFrame with status brackets
        status_bracket_map = {
            "overdue": "[OVERDUE]",
            "due_soon": "[DUE SOON]",
            "not_yet_due": "[NOT YET DUE]",
            "no_due_date": "[NO DUE DATE]",
        }

        table_rows = []
        for rank, r in enumerate(prioritized_records, start=1):
            raw_status = r.due_status(reference_date)
            table_rows.append({
                "Priority": rank,
                "CVE ID": r.cve_id,
                "Vendor / Project": r.vendor_project or "(missing)",
                "Product": r.product or "(missing)",
                "Due Date": r.due_date.isoformat() if r.due_date else "None",
                "Days Until Due": r.days_until_due(reference_date),
                "Status": status_bracket_map.get(raw_status, raw_status),
                "Date Added": r.date_added.isoformat() if r.date_added else "None",
                "Ransomware Use": r.known_ransomware_campaign_use or "Unknown",
                "Short Description": r.short_description or "",
            })

        df_worklist = pd.DataFrame(table_rows)

        # Quick Search inside filtered table
        search_kw = st.text_input(
            "// QUICK SEARCH INSIDE SELECTED WORKLIST (CVE, VENDOR, PRODUCT, KEYWORD):",
            placeholder="Type keyword to filter current table..."
        )
        if search_kw.strip():
            kw = search_kw.strip().lower()
            df_worklist = df_worklist[
                df_worklist["CVE ID"].str.lower().str.contains(kw) |
                df_worklist["Vendor / Project"].str.lower().str.contains(kw) |
                df_worklist["Product"].str.lower().str.contains(kw) |
                df_worklist["Short Description"].str.lower().str.contains(kw)
            ]

        # Interactive Dataframe
        st.dataframe(
            df_worklist.drop(columns=["Short Description"]),
            width="stretch",
            hide_index=True,
            column_config={
                "Priority": st.column_config.NumberColumn("Priority", width="small"),
                "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
                "Days Until Due": st.column_config.NumberColumn("Days Left", width="small"),
                "Status": st.column_config.TextColumn("Deadline Status", width="small"),
                "Ransomware Use": st.column_config.TextColumn("Ransomware", width="small"),
            }
        )

        # Export Worklist Section
        st.markdown("""
        <div style="margin-top: 14px; margin-bottom: 8px;">
            <div style="font-size: 0.95rem; font-weight: 800; color: #FFFFFF;">
                // EXPORT REMEDIATION WORKLIST
            </div>
            <div style="font-size: 0.74rem; color: #94A3B8; font-family: 'JetBrains Mono', monospace;">
                Download auditable, prioritized queue formatted for enterprise ticketing or forensic analysis.
            </div>
        </div>
        """, unsafe_allow_html=True)

        export_c1, export_c2 = st.columns(2)

        with export_c1:
            csv_buffer = io.StringIO()
            provenance = (
                f"# Catalog version: {worklist_metadata.get('catalog_version', 'Unknown')}; "
                f"Download date: {worklist_metadata.get('download_date') or 'Unknown'}; "
                f"Reference date: {worklist.reference_date}; Due soon: 0-{due_soon_window} days"
            ).replace("\r", " ").replace("\n", " ")
            csv_buffer.write(provenance + "\n")
            writer = csv.writer(csv_buffer, lineterminator="\n")
            writer.writerow(WORKLIST_CSV_COLUMNS)
            for record in prioritized_records:
                values = [
                    record.cve_id, record.vendor_project, record.product,
                    record.date_added, record.due_date,
                    record.due_status(worklist.reference_date) == "overdue",
                    record.days_until_due(worklist.reference_date),
                    record.age_in_days(worklist.reference_date),
                    record.known_ransomware_campaign_use, record.required_action,
                ]
                writer.writerow([
                    value.isoformat() if isinstance(value, date) else value
                    for value in values
                ])
            st.download_button(
                label="[ DOWNLOAD WORKLIST (CSV) ]",
                data=csv_buffer.getvalue().encode("utf-8"),
                file_name=f"prioritized_worklist_{reference_date}.csv",
                mime="text/csv",
                help="Includes CISA provenance header on line 1."
            )

        with export_c2:
            json_export = json.dumps(
                [vars(r) for r in prioritized_records],
                default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o),
                indent=2
            )
            st.download_button(
                label="[ DOWNLOAD WORKLIST (JSON) ]",
                data=json_export.encode("utf-8"),
                file_name=f"prioritized_worklist_{reference_date}.json",
                mime="application/json"
            )


# -----------------------------------------------------------------------------
# Tab 2: Visual Analytics (Matplotlib Charts)
# -----------------------------------------------------------------------------
with tab_charts:
    st.markdown("""
    <div style="margin-bottom: 10px;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">
            // ANALYTIC TELEMETRY &amp; VISUAL MODELS
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hud-card hud-card-accent-cyan" style="padding: 12px 18px; margin-bottom: 16px;">
        <div style="font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #38BDF8; margin-bottom: 4px;">
            // DEFENSIVE OPERATIONAL PRINCIPLE [COUNTS != RISK]
        </div>
        <div style="font-size: 0.84rem; color: #CBD5E1; line-height: 1.55;">
            High vendor or product counts reflect broad catalog tracking, transparent vulnerability disclosure, and market adoption—not poor security posture or an organization's specific exposure.
        </div>
    </div>
    """, unsafe_allow_html=True)

    chart_c1, chart_c2 = st.columns(2)

    with chart_c1:
        st.markdown("**1. DEADLINES AT REFERENCE DATE**")
        fig1, ax1 = plt.subplots(figsize=(8, 4.6), dpi=150)
        apply_cyber_hud_chart_style(fig1, ax1, f"STATUS AT {reference_date}")
        counts = [stats["overdue_count"], stats["due_soon_count"], stats["not_yet_due_count"]]
        labels = ["OVERDUE (<0d)", f"DUE SOON (0–{due_soon_window}d)", f"NOT YET DUE (>{due_soon_window}d)"]
        colors = [COLOR_HUD_RED, COLOR_HUD_AMBER, COLOR_HUD_GREEN]
        bars = ax1.bar(labels, counts, color=colors, edgecolor="#FFFFFF", linewidth=1.0)
        ax1.bar_label(bars, padding=4, color="#FFFFFF", fontweight="bold", fontsize=9.5)
        ax1.set_ylabel("Records", color="#CBD5E1")
        fig1.tight_layout()
        st.pyplot(fig1)
        plt.close(fig1)

    with chart_c2:
        st.markdown("**2. TOP 10 VENDORS BY CATALOG PRESENCE**")
        vendors = count_by_vendor(selected)
        fig2, ax2 = plt.subplots(figsize=(8, 4.6), dpi=150)
        apply_cyber_hud_chart_style(fig2, ax2, "TOP 10 VENDORS [COUNTS != RISK]")
        top_items = sorted(vendors.items(), key=lambda item: (-item[1], item[0]))[:10]
        if top_items:
            names, counts_v = zip(*top_items)
            bars2 = ax2.barh(names, counts_v, color=COLOR_HUD_CYAN, edgecolor="#FFFFFF", linewidth=0.8)
            ax2.bar_label(bars2, padding=4, color="#FFFFFF", fontweight="bold", fontsize=9)
            ax2.invert_yaxis()
            ax2.set_xlabel("Vulnerabilities", color="#CBD5E1")
        fig2.tight_layout()
        st.pyplot(fig2)
        plt.close(fig2)

    chart_c3, chart_c4 = st.columns(2)

    with chart_c3:
        st.markdown("**3. MONTHLY ADDITION TREND**")
        fig3, ax3 = plt.subplots(figsize=(8, 4.6), dpi=150)
        apply_cyber_hud_chart_style(fig3, ax3, "KEV ADDITIONS BY MONTH [TELEMETRY]")
        dated_records = [r for r in selected if r.date_added]
        if dated_records:
            monthly_counts = {}
            for r in dated_records:
                month_key = r.date_added.strftime("%Y-%m")
                monthly_counts[month_key] = monthly_counts.get(month_key, 0) + 1
            sorted_months = sorted(monthly_counts.keys())
            ax3.plot(
                sorted_months,
                [monthly_counts[m] for m in sorted_months],
                marker="o", color=COLOR_HUD_CYAN, linewidth=2.2,
                markerfacecolor="#FFFFFF", markeredgecolor=COLOR_HUD_CYAN, markersize=5,
            )
            ax3.fill_between(
                sorted_months,
                [monthly_counts[m] for m in sorted_months],
                alpha=0.18, color=COLOR_HUD_CYAN,
            )
            ax3.set_xticks(range(0, len(sorted_months), max(1, len(sorted_months) // 6)))
            ax3.tick_params(axis="x", rotation=35, colors="#FFFFFF")
            ax3.set_ylabel("Additions", color="#CBD5E1")
        fig3.tight_layout()
        st.pyplot(fig3)
        plt.close(fig3)

    with chart_c4:
        st.markdown("**4. KNOWN VS UNKNOWN RANSOMWARE USE**")
        fig4, ax4 = plt.subplots(figsize=(8, 4.6), dpi=150)
        apply_cyber_hud_chart_style(fig4, ax4, "RANSOMWARE CAMPAIGN ASSOCIATIONS")
        rw_known = sum(1 for r in selected if r.known_ransomware_campaign_use == "Known")
        rw_unknown = sum(1 for r in selected if r.known_ransomware_campaign_use == "Unknown")
        rw_bars = ax4.bar(
            ["KNOWN CAMPAIGN USE", "UNKNOWN / UNCONFIRMED"],
            [rw_known, rw_unknown],
            color=[COLOR_HUD_RED, COLOR_HUD_CYAN],
            edgecolor="#FFFFFF", linewidth=1.0,
        )
        ax4.bar_label(rw_bars, padding=4, color="#FFFFFF", fontweight="bold", fontsize=9.5)
        ax4.set_ylabel("Records", color="#CBD5E1")
        fig4.tight_layout()
        st.pyplot(fig4)
        plt.close(fig4)


# -----------------------------------------------------------------------------
# Tab 3: CVE Inspector
# -----------------------------------------------------------------------------
with tab_inspector:
    st.markdown("""
    <div style="margin-bottom: 10px;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">
            // INDIVIDUAL VULNERABILITY INSPECTOR
        </div>
        <div style="font-size: 0.8rem; color: #94A3B8; font-family: 'JetBrains Mono', monospace;">
            Deep telemetry inspection: mandated remediation directives, technical advisories, and CWE weakness classification.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not prioritized_records:
        st.markdown("""
        <div class="hud-card hud-card-accent-amber">
            <span class="hud-tag hud-tag-amber">[INSPECT.EMPTY]</span> No records available to inspect in active selection.
        </div>
        """, unsafe_allow_html=True)
    else:
        cve_options = [f"{r.cve_id} // {r.vendor_project or 'Unknown'} ({r.product or 'Unknown'})" for r in prioritized_records[:100]]
        selected_cve_label = st.selectbox(
            "// SELECT VULNERABILITY TO INSPECT (SHOWING TOP 100 IN PRIORITY ORDER):",
            options=cve_options
        )

        selected_cve_id = selected_cve_label.split(" // ")[0]
        inspected_record = next((r for r in prioritized_records if r.cve_id == selected_cve_id), None)

        if inspected_record:
            st.markdown(f"""
            <div style="font-size: 1.3rem; font-weight: 800; color: #FFFFFF; margin-top: 6px; margin-bottom: 12px;">
                <span class="hud-slash">//</span>{inspected_record.cve_id} : {inspected_record.vulnerability_name or 'NO FORMAL TITLE'}
            </div>
            """, unsafe_allow_html=True)

            detail_c1, detail_c2 = st.columns([2, 1])

            with detail_c1:
                # Description
                st.markdown(f"""
                <div class="hud-card" style="margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; font-family: 'JetBrains Mono', monospace; color: #38BDF8; font-weight: 700; margin-bottom: 6px;">
                        // VULNERABILITY SUMMARY &amp; ATTACK VECTOR
                    </div>
                    <div style="font-size: 0.86rem; line-height: 1.6; color: #E2E8F0;">
                        {inspected_record.short_description or 'No description provided.'}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # CISA Mandate Action
                st.markdown(f"""
                <div class="hud-card hud-card-accent-red" style="border: 1.5px solid rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.05); margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-size: 0.72rem; font-family: 'JetBrains Mono', monospace; color: #EF4444; font-weight: 700;">
                            // CISA BINDING REQUIRED ACTION [REMEDIATION MANDATE]
                        </span>
                        <span class="hud-tag hud-tag-red">[MANDATE: BOD 22-01]</span>
                    </div>
                    <div style="color: #FFFFFF; font-weight: 700; font-size: 0.88rem; line-height: 1.5;">
                        {inspected_record.required_action or 'No action recorded.'}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if inspected_record.notes:
                    st.markdown(f"""
                    <div class="hud-card">
                        <div style="font-size: 0.72rem; font-family: 'JetBrains Mono', monospace; color: #94A3B8; font-weight: 700; margin-bottom: 6px;">
                            // TECHNICAL NOTES &amp; ADVISORIES
                        </div>
                        <div style="font-size: 0.84rem; line-height: 1.5; color: #CBD5E1;">
                            {inspected_record.notes}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            with detail_c2:
                insp_status = inspected_record.due_status(reference_date)
                if insp_status == "overdue":
                    tag_class = "hud-tag-red"
                    tag_label = "[OVERDUE]"
                elif insp_status == "due_soon":
                    tag_class = "hud-tag-amber"
                    tag_label = "[DUE SOON]"
                elif insp_status == "not_yet_due":
                    tag_class = "hud-tag-green"
                    tag_label = "[NOT YET DUE]"
                else:
                    tag_class = "hud-tag-cyan"
                    tag_label = "[NO DUE DATE]"

                rw_label = inspected_record.known_ransomware_campaign_use or "Unknown"
                rw_class = "hud-tag-red" if rw_label == "Known" else "hud-tag-cyan"

                cwes_str = ', '.join(inspected_record.cwes) if inspected_record.cwes else 'None Cataloged'

                st.markdown(f"""
                <div class="hud-card">
                    <div style="font-size: 0.74rem; font-family: 'JetBrains Mono', monospace; color: #38BDF8; font-weight: 700; margin-bottom: 10px;">
                        // LIFECYCLE &amp; TELEMETRY
                    </div>
                    <div style="font-size: 0.82rem; line-height: 1.8; color: #CBD5E1;">
                        <div><strong>VENDOR:</strong> <span style="color: #FFFFFF;">{inspected_record.vendor_project}</span></div>
                        <div><strong>PRODUCT:</strong> <span style="color: #FFFFFF;">{inspected_record.product}</span></div>
                        <div><strong>DATE ADDED:</strong> <span style="color: #FFFFFF;">{inspected_record.date_added}</span></div>
                        <div><strong>DUE DATE:</strong> <span style="color: #FFFFFF;">{inspected_record.due_date}</span></div>
                        <div><strong>DAYS REMAINING:</strong> <span style="color: #FFFFFF;">{inspected_record.days_until_due(reference_date)}</span></div>
                        <div style="margin-top: 4px;"><strong>DEADLINE STATUS:</strong> <span class="hud-tag {tag_class}">{tag_label}</span></div>
                        <div style="margin-top: 4px;"><strong>RANSOMWARE:</strong> <span class="hud-tag {rw_class}">[{rw_label.upper()}]</span></div>
                        <div style="margin-top: 4px;"><strong>WEAKNESS (CWE):</strong> <span style="color: #FFFFFF; font-family: 'JetBrains Mono', monospace;">{cwes_str}</span></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Tab 4: Data Quality & Audit Report
# -----------------------------------------------------------------------------
with tab_quality:
    st.markdown("""
    <div style="margin-bottom: 10px;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">
            // DEFENSIVE DATA-QUALITY &amp; INTEGRITY AUDIT
        </div>
        <div style="font-size: 0.8rem; color: #94A3B8; font-family: 'JetBrains Mono', monospace;">
            Conducted systematically across the complete un-filtered catalog snapshot to ensure data defects are never masked.
        </div>
    </div>
    """, unsafe_allow_html=True)

    audit_c1, audit_c2, audit_c3, audit_c4 = st.columns(4)

    with audit_c1:
        st.markdown(f"""
        <div class="hud-kpi-card">
            <div class="hud-kpi-header">
                <span><span class="hud-slash">//</span>TOTAL ISSUES</span>
                <span class="hud-tag {'hud-tag-green' if data_quality['total_issues'] == 0 else 'hud-tag-red'}">[{'AUDIT.PASS' if data_quality['total_issues'] == 0 else 'AUDIT.ALERT'}]</span>
            </div>
            <div class="hud-kpi-value">{data_quality['total_issues']}</div>
            <div class="hud-kpi-delta">RECORD DEFECTS</div>
        </div>
        """, unsafe_allow_html=True)

    with audit_c2:
        st.markdown(f"""
        <div class="hud-kpi-card">
            <div class="hud-kpi-header">
                <span><span class="hud-slash">//</span>AFFECTED ROWS</span>
                <span class="hud-tag hud-tag-cyan">[SOURCE: RAW]</span>
            </div>
            <div class="hud-kpi-value">{data_quality['affected_record_count']}</div>
            <div class="hud-kpi-delta">OF {len(all_records):,} TOTAL</div>
        </div>
        """, unsafe_allow_html=True)

    with audit_c3:
        st.markdown(f"""
        <div class="hud-kpi-card">
            <div class="hud-kpi-header">
                <span><span class="hud-slash">//</span>DUPLICATE CVES</span>
                <span class="hud-tag hud-tag-cyan">[RFC INTEGRITY]</span>
            </div>
            <div class="hud-kpi-value">{len(data_quality['duplicate_cve_ids'])}</div>
            <div class="hud-kpi-delta">COLLISIONS DETECTED</div>
        </div>
        """, unsafe_allow_html=True)

    with audit_c4:
        st.markdown(f"""
        <div class="hud-kpi-card">
            <div class="hud-kpi-header">
                <span><span class="hud-slash">//</span>MISSING DUE DATES</span>
                <span class="hud-tag hud-tag-cyan">[MANDATE CHECK]</span>
            </div>
            <div class="hud-kpi-value">{len(data_quality['missing_due_date'])}</div>
            <div class="hud-kpi-delta">RECORDS LACKING DATES</div>
        </div>
        """, unsafe_allow_html=True)

    if data_quality["total_issues"] == 0:
        st.markdown("""
        <div class="hud-card hud-card-accent-green" style="margin-top: 14px;">
            <div style="font-weight: 800; color: #10B981; font-size: 0.88rem; margin-bottom: 4px;">
                <span class="hud-tag hud-tag-green">[AUDIT.PASS]</span> ZERO DATA-QUALITY DEFECTS DETECTED
            </div>
            <div style="font-size: 0.84rem; color: #CBD5E1; line-height: 1.55;">
                All catalog records adhere strictly to CISA RFC-compliant date structures, unique identifier integrity, and required schema fields.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="hud-card hud-card-accent-amber" style="margin-top: 14px;">
            <div style="font-weight: 800; color: #F59E0B; font-size: 0.88rem; margin-bottom: 4px;">
                <span class="hud-tag hud-tag-amber">[AUDIT.FINDINGS]</span> DATA-QUALITY DEFECTS SURFACED
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.json(data_quality)


# -----------------------------------------------------------------------------
# Tab 5: Prioritization Policy & Playbook
# -----------------------------------------------------------------------------
with tab_docs:
    st.markdown("""
    <div style="margin-bottom: 10px;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">
            // AUDITABLE PRIORITIZATION POLICY &amp; DEFENSIVE CONTRACT
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hud-card">
        <h4 style="color: #38BDF8; font-size: 1rem; margin-top: 0;"><span class="hud-slash">//</span>1. The Deterministic Priority Queue</h4>
        <p style="font-size: 0.85rem; line-height: 1.6; color: #CBD5E1;">
            In defensive vulnerability management, inventing arbitrary numeric threat scores or synthetic risk formulas absent from official catalogs can mislead operations teams. This platform implements strict, auditable sorting:
        </p>
        <ol style="font-size: 0.85rem; line-height: 1.7; color: #E2E8F0;">
            <li><strong>[RULE 1] Overdue Records First:</strong> Ranked from most negative deadline offset to least negative (furthest overdue first).</li>
            <li><strong>[RULE 2] Valid Upcoming Deadlines Next:</strong> Sorted chronologically, earliest due date first.</li>
            <li><strong>[RULE 3] Records Without Usable Due Dates Last:</strong> Retained safely in priority order without discarding.</li>
            <li><strong>[RULE 4] Deterministic Tie-Breaking:</strong> Oldest <code>date_added</code> first; completely tied entries preserve input order.</li>
        </ol>
    </div>

    <div class="hud-card" style="margin-top: 14px;">
        <h4 style="color: #38BDF8; font-size: 1rem; margin-top: 0;"><span class="hud-slash">//</span>2. Defensive Operational Principles</h4>
        <div style="font-size: 0.85rem; line-height: 1.7; color: #CBD5E1;">
            <p><strong><span class="hud-tag hud-tag-cyan">[DEFENSIVE SCOPE]</span> No Weaponization:</strong> The platform performs catalog modeling, date arithmetic, and defensive prioritization only. No target exploitation, penetration testing, or network port probing is performed.</p>
            <p><strong><span class="hud-tag hud-tag-cyan">[COUNTS ≠ RISK]</span> Reporting Maturity:</strong> Vendor counts describe catalog presence and reporting maturity, not vendor software insecurity or an enterprise's specific exposure.</p>
            <p><strong><span class="hud-tag hud-tag-cyan">[RANSOMWARE UNKNOWN]</span> Absence of Proof:</strong> <code>Unknown</code> indicates unconfirmed campaign use in public telemetry, not confirmed absence of ransomware threat.</p>
            <p><strong><span class="hud-tag hud-tag-cyan">[BOD 22-01 MANDATE]</span> Federal Compliance:</strong> Mandated compliance deadlines reflect federal operational urgency; overdue items must receive immediate mitigation.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
