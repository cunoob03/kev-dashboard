"""
CISA KEV Prioritization Dashboard & Remediation Hub
Interactive Streamlit Web Application for Defensive Vulnerability Prioritization.
"""

import json
import tempfile
from datetime import date, datetime
from pathlib import Path
import io

import pandas as pd
import requests
import streamlit as st
import matplotlib.pyplot as plt

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

# -- Semantic Color Palette ---------------------------------------------------
COLOR_BG_PRIMARY = "#0D1117"
COLOR_BG_CARD = "#161B22"
COLOR_TEXT = "#E6EDF3"
COLOR_TEXT_SECONDARY = "#8B949E"
COLOR_OVERDUE = "#BF4545"
COLOR_DUE_SOON = "#DD982D"
COLOR_SAFE = "#438B69"
COLOR_PRIMARY = "#3979A6"
COLOR_BORDER_GLOW = "rgba(57, 121, 166, 0.3)"

# -----------------------------------------------------------------------------
# Streamlit Page Config
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CISA KEV Prioritization Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -- Dark Cybersecurity Theme CSS ----------------------------------------------
st.markdown("""
<style>
    /* Import Montserrat from Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap');

    /* Global typography */
    html, body, [class*="st-"], .stApp {
        font-family: 'Montserrat', 'Segoe UI', sans-serif;
    }

    /* Main app background */
    .stApp {
        background-color: #0D1117;
        color: #E6EDF3;
    }

    /* Glass-morphism metric cards with blue border glow */
    .metric-card {
        background: linear-gradient(135deg, #161B22 0%, #1C2333 100%);
        border: 1px solid rgba(57, 121, 166, 0.3);
        border-radius: 10px;
        padding: 18px 22px;
        box-shadow: 0 0 15px rgba(57, 121, 166, 0.08),
                    0 4px 12px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(8px);
        transition: border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: rgba(57, 121, 166, 0.6);
    }

    /* Semantic status badges */
    .badge-overdue {
        color: #BF4545;
        font-weight: 700;
        text-shadow: 0 0 6px rgba(191, 69, 69, 0.3);
    }
    .badge-due-soon {
        color: #DD982D;
        font-weight: 700;
        text-shadow: 0 0 6px rgba(221, 152, 45, 0.3);
    }
    .badge-safe {
        color: #438B69;
        font-weight: 700;
        text-shadow: 0 0 6px rgba(67, 139, 105, 0.3);
    }

    /* Dark-styled tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background-color: #161B22;
        border-radius: 8px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 12px 24px;
        font-weight: 600;
        color: #8B949E;
        border-radius: 6px;
        transition: all 0.2s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        color: #E6EDF3;
        background-color: rgba(57, 121, 166, 0.1);
    }
    .stTabs [aria-selected="true"] {
        color: #E6EDF3 !important;
        background-color: rgba(57, 121, 166, 0.2) !important;
        border-bottom: 2px solid #3979A6 !important;
    }

    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0D1117;
        border-right: 1px solid rgba(57, 121, 166, 0.15);
    }

    /* Streamlit metric overrides for dark theme */
    [data-testid="stMetricValue"] {
        color: #E6EDF3;
    }
    [data-testid="stMetricDelta"] {
        color: #8B949E;
    }

    /* Dataframe / table styling */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }

    /* Input elements */
    .stSelectbox label, .stMultiSelect label, .stDateInput label,
    .stTextInput label, .stSlider label {
        color: #8B949E !important;
        font-weight: 500;
    }

    /* Divider lines */
    hr {
        border-color: rgba(57, 121, 166, 0.15);
    }

    /* Caption text */
    .stCaption {
        color: #8B949E;
    }

    /* Better scrollbar for dark mode */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #0D1117;
    }
    ::-webkit-scrollbar-thumb {
        background: #30363D;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #3979A6;
    }
</style>
""", unsafe_allow_html=True)

CISA_LIVE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# -----------------------------------------------------------------------------
# Data Loading & Caching
# -----------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def get_catalog_from_file(catalog_path: Path):
    """Load catalog from local JSON snapshot."""
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


# -----------------------------------------------------------------------------
# Sidebar: Provenance & Filters
# -----------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ CISA KEV Hub")
    st.caption("Defensive Prioritization & Remediation Platform")

    st.markdown("---")
    st.subheader("Data Source Mode")

    sync_col1, sync_col2 = st.columns([2, 1])
    with sync_col1:
        if st.session_state.use_live_cisa:
            st.success("🟢 Using Live CISA Feed")
        else:
            st.info("📦 Bundled Frozen Snapshot")

    with sync_col2:
        if not st.session_state.use_live_cisa:
            if st.button("Fetch Live", help="Download current feed from CISA.gov"):
                with st.spinner("Connecting to CISA..."):
                    try:
                        meta, recs = fetch_live_catalog()
                        st.session_state.live_metadata = meta
                        st.session_state.live_records = recs
                        st.session_state.use_live_cisa = True
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to fetch live feed: {e}")
        else:
            if st.button("Reset Frozen"):
                st.session_state.use_live_cisa = False
                st.rerun()

    # Determine Active Catalog
    if st.session_state.use_live_cisa and st.session_state.live_records:
        raw_metadata = st.session_state.live_metadata
        all_records = st.session_state.live_records
        catalog_source_label = "Live CISA Feed"
    else:
        raw_metadata, all_records = get_catalog_from_file(config.CATALOG_PATH)
        catalog_source_label = f"Frozen Snapshot ({config.CATALOG_PATH.name})"

    st.markdown("---")
    st.subheader("Filter Controls")

    # Reference Date Picker
    default_ref = config.DEFAULT_REFERENCE_DATE
    ref_date_input = st.date_input(
        "Reference Date",
        value=default_ref,
        help="Date against which age and deadline offsets are calculated."
    )
    if isinstance(ref_date_input, datetime):
        reference_date = ref_date_input.date()
    else:
        reference_date = ref_date_input

    # Due Soon Window Slider
    due_soon_window = st.slider(
        "Due-Soon Window (Days)",
        min_value=1,
        max_value=60,
        value=config.DUE_SOON_DAYS,
        help="Days from reference date considered 'Due Soon' (inclusive)."
    )

    # Unique Vendors & Products
    unique_vendors = sorted({r.vendor_project for r in all_records if r.vendor_project})
    selected_vendors = st.multiselect("Filter by Vendor(s)", options=unique_vendors)

    # Product Text Search
    product_query = st.text_input("Filter by Product", placeholder="e.g. Windows, IOS, Acrobat")

    # Ransomware Campaign Use
    ransomware_filter = st.selectbox(
        "Ransomware Campaign Use",
        options=["All", "Known", "Unknown"],
        index=0
    )

    # Deadline Status Filter
    due_status_filter = st.selectbox(
        "Deadline Status",
        options=["All", "overdue", "due_soon", "not_yet_due", "no_due_date"],
        format_func=lambda s: {
            "All": "All Statuses",
            "overdue": "🚨 Overdue (< 0 days)",
            "due_soon": f"⚠️ Due Soon (0–{due_soon_window} days)",
            "not_yet_due": f"🟢 Not Yet Due (> {due_soon_window} days)",
            "no_due_date": "⚪ No Due Date Listed",
        }.get(s, s),
        index=0
    )

    # Date Added Range
    st.markdown("**Date Added Range**")
    date_col1, date_col2 = st.columns(2)
    with date_col1:
        start_date = st.date_input("From", value=None)
    with date_col2:
        end_date = st.date_input("To", value=None)


# -----------------------------------------------------------------------------
# Data Filtering & Prioritization Pipeline
# -----------------------------------------------------------------------------
config.DUE_SOON_DAYS = due_soon_window
selected = list(all_records)
applied_filters = []

# Apply Vendor Filter
if selected_vendors:
    selected = [r for r in selected if r.vendor_project and r.vendor_project in selected_vendors]
    applied_filters.append(f"vendor in {selected_vendors}")

# Apply Product Filter
if product_query.strip():
    selected = filter_by_product(selected, product_query.strip())
    applied_filters.append(f"product = '{product_query.strip()}'")

# Apply Ransomware Filter
if ransomware_filter != "All":
    selected = filter_by_ransomware(selected, ransomware_filter)
    applied_filters.append(f"ransomware = '{ransomware_filter}'")

# Apply Deadline Status Filter
if due_status_filter != "All":
    selected = filter_by_due_status(selected, due_status_filter, reference_date)
    applied_filters.append(f"due_status = '{due_status_filter}'")

# Apply Date Range Filter
if start_date or end_date:
    selected = filter_by_date_range(selected, start_date, end_date)
    applied_filters.append(f"date_added between {start_date or 'any'} and {end_date or 'any'}")

# Build Prioritized Worklist Object
worklist_metadata = dict(raw_metadata)
worklist_metadata["reference_date"] = reference_date.isoformat()
worklist = PrioritizedWorklist(selected, worklist_metadata, applied_filters, reference_date=reference_date)
stats = worklist.summary_stats()
data_quality = find_data_quality_issues(all_records)


# -----------------------------------------------------------------------------
# Main Header & Provenance Status Bar
# -----------------------------------------------------------------------------
st.title("🛡️ CISA KEV Prioritization Dashboard")
st.markdown("#### Defensive Vulnerability Prioritization & Audit Platform")

provenance_col1, provenance_col2, provenance_col3, provenance_col4 = st.columns(4)
with provenance_col1:
    st.caption(f"**Catalog Version:** `{raw_metadata.get('catalog_version', 'Unknown')}`")
with provenance_col2:
    st.caption(f"**Catalog Release:** `{raw_metadata.get('date_released', 'Unknown')[:10]}`")
with provenance_col3:
    st.caption(f"**Reference Date:** `{reference_date.isoformat()}`")
with provenance_col4:
    st.caption(f"**Data Mode:** `{catalog_source_label}`")

# -----------------------------------------------------------------------------
# Key Metric Cards (KPIs)
# -----------------------------------------------------------------------------
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.metric(label="Selected Records", value=f"{stats['total']:,}", delta=f"of {len(all_records):,} Total")
with kpi2:
    st.metric(label="🚨 Overdue", value=f"{stats['overdue_count']:,}", delta="Urgent Action" if stats['overdue_count'] else None, delta_color="inverse")
with kpi3:
    st.metric(label="⚠️ Due Soon", value=f"{stats['due_soon_count']:,}", delta=f"0–{due_soon_window} days" if stats['due_soon_count'] else None)
with kpi4:
    st.metric(label="🎯 Ransomware Known", value=f"{stats['ransomware_known_count']:,}", delta="High Threat")
with kpi5:
    mean_age = f"{stats['mean_age_days']:.0f} d" if stats['mean_age_days'] is not None else "N/A"
    median_age = f"{stats['median_age_days']:.0f} d" if stats['median_age_days'] is not None else "N/A"
    st.metric(label="Median Catalog Age", value=median_age, delta=f"Mean: {mean_age}")

st.markdown("---")


# -- Chart Styling Helper ------------------------------------------------------
def apply_dark_chart_style(fig, ax, title_text=""):
    """Apply consistent dark theme to matplotlib figures in the dashboard."""
    fig.set_facecolor(COLOR_BG_CARD)
    ax.set_facecolor(COLOR_BG_CARD)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines["bottom"].set_color(COLOR_TEXT_SECONDARY)
    ax.spines["left"].set_color(COLOR_TEXT_SECONDARY)
    ax.tick_params(colors=COLOR_TEXT_SECONDARY, which="both")
    ax.xaxis.label.set_color(COLOR_TEXT_SECONDARY)
    ax.yaxis.label.set_color(COLOR_TEXT_SECONDARY)
    ax.grid(axis="y", color="#30363D", alpha=0.4, linewidth=0.5)
    ax.set_axisbelow(True)
    if title_text:
        ax.set_title(title_text, fontweight="bold", loc="left", color=COLOR_TEXT, fontsize=12)


# -----------------------------------------------------------------------------
# Tabbed Navigation
# -----------------------------------------------------------------------------
tab_worklist, tab_charts, tab_inspector, tab_quality, tab_docs = st.tabs([
    "📋 Prioritized Worklist",
    "📊 Visual Analytics",
    "🔍 CVE Inspector",
    "🛡️ Data Quality & Audit",
    "📖 Prioritization Policy"
])


# -----------------------------------------------------------------------------
# Tab 1: Prioritized Worklist (Remediation Hub)
# -----------------------------------------------------------------------------
with tab_worklist:
    st.subheader("Deterministic Remediation Worklist")
    st.caption("Sorted strictly: **Overdue first** (most overdue first) $\\to$ **Upcoming deadlines** $\\to$ **Missing deadlines** $\\to$ **Oldest date added**.")

    prioritized_records = worklist.get_records()

    if not prioritized_records:
        st.warning("No vulnerability records match the selected filter criteria.")
    else:
        # Build pandas DataFrame for interactive display
        table_rows = []
        for rank, r in enumerate(prioritized_records, start=1):
            table_rows.append({
                "Priority": rank,
                "CVE ID": r.cve_id,
                "Vendor / Project": r.vendor_project or "(missing)",
                "Product": r.product or "(missing)",
                "Due Date": r.due_date.isoformat() if r.due_date else "None",
                "Days Until Due": r.days_until_due(reference_date),
                "Status": r.due_status(reference_date),
                "Date Added": r.date_added.isoformat() if r.date_added else "None",
                "Ransomware Use": r.known_ransomware_campaign_use or "Unknown",
                "Short Description": r.short_description or "",
            })

        df_worklist = pd.DataFrame(table_rows)

        # Quick Search inside filtered table
        search_kw = st.text_input("Quick Search inside selected worklist (by CVE, Vendor, Product, or keyword):", placeholder="Type keyword...")
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
            use_container_width=True,
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
        st.markdown("#### 📥 Export Prioritized Worklist")
        export_col1, export_col2 = st.columns(2)

        with export_col1:
            # Generate official CSV with provenance header
            csv_buffer = io.StringIO()
            provenance_line = (
                f"# Catalog: {raw_metadata.get('catalog_version', 'Unknown')} | "
                f"Reference: {reference_date} | "
                f"Due soon: 0-{due_soon_window} days | "
                f"Exported: {date.today().isoformat()}\n"
            )
            csv_buffer.write(provenance_line)
            df_worklist.drop(columns=["Priority", "Short Description"]).to_csv(csv_buffer, index=False)
            st.download_button(
                label="Download Prioritized Worklist (CSV)",
                data=csv_buffer.getvalue().encode("utf-8"),
                file_name=f"prioritized_worklist_{reference_date}.csv",
                mime="text/csv",
                help="Includes CISA provenance header on line 1."
            )

        with export_col2:
            json_export = json.dumps(
                [vars(r) for r in prioritized_records],
                default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o),
                indent=2
            )
            st.download_button(
                label="Download Worklist (JSON)",
                data=json_export.encode("utf-8"),
                file_name=f"prioritized_worklist_{reference_date}.json",
                mime="application/json"
            )


# -----------------------------------------------------------------------------
# Tab 2: Visual Analytics
# -----------------------------------------------------------------------------
with tab_charts:
    st.subheader("Analytical Visualizations")
    st.info("💡 **Defensive Security Principle: 'Counts ≠ Risk'**\n\nHigh vendor or product counts reflect broad catalog tracking, transparent vulnerability disclosure, and market adoption—not poor security posture or an organization's specific exposure.")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("##### 1. Deadlines at Reference Date")
        fig1, ax1 = plt.subplots(figsize=(8, 5))
        apply_dark_chart_style(fig1, ax1, f"Status at {reference_date}")
        counts = [stats["overdue_count"], stats["due_soon_count"], stats["not_yet_due_count"]]
        labels = ["Overdue (<0d)", f"Due Soon (0–{due_soon_window}d)", f"Not Yet Due (>{due_soon_window}d)"]
        colors = [COLOR_OVERDUE, COLOR_DUE_SOON, COLOR_SAFE]
        bars = ax1.bar(labels, counts, color=colors, edgecolor="#0D1117", linewidth=0.5)
        ax1.bar_label(bars, padding=3, color=COLOR_TEXT, fontweight="bold")
        ax1.set_ylabel("Records", color=COLOR_TEXT_SECONDARY)
        ax1.tick_params(axis="x", colors=COLOR_TEXT_SECONDARY)
        fig1.tight_layout()
        st.pyplot(fig1)
        plt.close(fig1)

    with chart_col2:
        st.markdown("##### 2. Top 10 Vendors by Catalog Presence")
        vendors = count_by_vendor(selected)
        fig2, ax2 = plt.subplots(figsize=(8, 5))
        apply_dark_chart_style(fig2, ax2, "Top Vendors (Counts != Risk)")
        top_items = sorted(vendors.items(), key=lambda item: (-item[1], item[0]))[:10]
        if top_items:
            names, counts_v = zip(*top_items)
            bars2 = ax2.barh(names, counts_v, color=COLOR_PRIMARY, edgecolor="#0D1117", linewidth=0.5)
            ax2.bar_label(bars2, padding=3, color=COLOR_TEXT, fontweight="bold")
            ax2.invert_yaxis()
            ax2.set_xlabel("Vulnerabilities", color=COLOR_TEXT_SECONDARY)
            ax2.tick_params(axis="y", colors=COLOR_TEXT_SECONDARY)
        fig2.tight_layout()
        st.pyplot(fig2)
        plt.close(fig2)

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        st.markdown("##### 3. Monthly Addition Trend")
        fig3, ax3 = plt.subplots(figsize=(8, 5))
        apply_dark_chart_style(fig3, ax3, "KEV Additions by Month")
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
                marker="o", color=COLOR_PRIMARY, linewidth=2,
                markerfacecolor=COLOR_TEXT, markeredgecolor=COLOR_PRIMARY, markersize=5,
            )
            ax3.fill_between(
                sorted_months,
                [monthly_counts[m] for m in sorted_months],
                alpha=0.1, color=COLOR_PRIMARY,
            )
            ax3.set_xticks(range(0, len(sorted_months), max(1, len(sorted_months) // 6)))
            ax3.tick_params(axis="x", rotation=35, colors=COLOR_TEXT_SECONDARY)
            ax3.set_ylabel("Additions", color=COLOR_TEXT_SECONDARY)
        fig3.tight_layout()
        st.pyplot(fig3)
        plt.close(fig3)

    with chart_col4:
        st.markdown("##### 4. Known vs Unknown Ransomware Use")
        fig4, ax4 = plt.subplots(figsize=(8, 5))
        apply_dark_chart_style(fig4, ax4, "Ransomware Associations")
        rw_known = sum(1 for r in selected if r.known_ransomware_campaign_use == "Known")
        rw_unknown = sum(1 for r in selected if r.known_ransomware_campaign_use == "Unknown")
        rw_bars = ax4.bar(
            ["Known Campaign Use", "Unknown / Unconfirmed"],
            [rw_known, rw_unknown],
            color=[COLOR_OVERDUE, COLOR_PRIMARY],
            edgecolor="#0D1117", linewidth=0.5,
        )
        ax4.bar_label(rw_bars, padding=3, color=COLOR_TEXT, fontweight="bold")
        ax4.set_ylabel("Records", color=COLOR_TEXT_SECONDARY)
        ax4.tick_params(axis="x", colors=COLOR_TEXT_SECONDARY)
        fig4.tight_layout()
        st.pyplot(fig4)
        plt.close(fig4)


# -----------------------------------------------------------------------------
# Tab 3: CVE Inspector
# -----------------------------------------------------------------------------
with tab_inspector:
    st.subheader("Individual Vulnerability Inspector")
    st.caption("Deep-dive into CISA's required remediation actions, technical notes, and CWE weakness classifications.")

    if not prioritized_records:
        st.info("No records to inspect.")
    else:
        cve_options = [f"{r.cve_id} — {r.vendor_project or 'Unknown'} ({r.product or 'Unknown'})" for r in prioritized_records[:100]]
        selected_cve_label = st.selectbox("Select a Vulnerability to Inspect (showing top 100 in priority order):", options=cve_options)

        selected_cve_id = selected_cve_label.split(" — ")[0]
        inspected_record = next((r for r in prioritized_records if r.cve_id == selected_cve_id), None)

        if inspected_record:
            st.markdown(f"### {inspected_record.cve_id}: {inspected_record.vulnerability_name or 'No Title'}")

            detail_col1, detail_col2 = st.columns([2, 1])

            with detail_col1:
                st.markdown("**Vulnerability Description:**")
                st.write(inspected_record.short_description or "No description provided.")

                st.markdown("**🛡️ CISA Required Action (Remediation Mandate):**")
                st.success(inspected_record.required_action or "No action recorded.")

                if inspected_record.notes:
                    st.markdown("**Technical Notes:**")
                    st.info(inspected_record.notes)

            with detail_col2:
                st.markdown("##### Lifecycle & Status")
                st.write(f"**Vendor / Project:** `{inspected_record.vendor_project}`")
                st.write(f"**Affected Product:** `{inspected_record.product}`")
                st.write(f"**Date Added to KEV:** `{inspected_record.date_added}`")
                st.write(f"**CISA Due Date:** `{inspected_record.due_date}`")
                st.write(f"**Days Until Due:** `{inspected_record.days_until_due(reference_date)}`")
                st.write(f"**Current Status:** `{inspected_record.due_status(reference_date)}`")
                st.write(f"**Ransomware Use:** `{inspected_record.known_ransomware_campaign_use}`")
                st.write(f"**Weakness (CWEs):** `{', '.join(inspected_record.cwes) if inspected_record.cwes else 'None'}`")


# -----------------------------------------------------------------------------
# Tab 4: Data Quality & Audit Report
# -----------------------------------------------------------------------------
with tab_quality:
    st.subheader("Defensive Data-Quality Diagnostics")
    st.caption("Conducted on the full source catalog prior to filtering, ensuring data defects are never masked.")

    audit_col1, audit_col2, audit_col3, audit_col4 = st.columns(4)
    with audit_col1:
        st.metric("Total Quality Issues", data_quality["total_issues"])
    with audit_col2:
        st.metric("Affected Source Records", data_quality["affected_record_count"])
    with audit_col3:
        st.metric("Duplicate CVE IDs", len(data_quality["duplicate_cve_ids"]))
    with audit_col4:
        st.metric("Missing Due Dates", len(data_quality["missing_due_date"]))

    if data_quality["total_issues"] == 0:
        st.success("✅ Zero data-quality defects detected in the active KEV catalog snapshot.")
    else:
        st.warning("Data quality findings identified:")
        st.json(data_quality)


# -----------------------------------------------------------------------------
# Tab 5: Prioritization Policy & Documentation
# -----------------------------------------------------------------------------
with tab_docs:
    st.subheader("Auditable Prioritization Policy")
    st.markdown("""
    ### Why Transparent Ordering?
    In defensive vulnerability management, inventing arbitrary numeric threat scores or synthetic risk formulas absent from official catalogs can mislead operations teams. This platform implements strict, auditable sorting:

    1. **Overdue Records First**: Ranked from most negative deadline offset to least negative (most urgent first).
    2. **Valid Future Deadlines Next**: Sorted earliest due date first.
    3. **Records Without Usable Due Dates Last**: Retained safely without discarding.
    4. **Deterministic Tie-Breaking**: Oldest `date_added` first; completely tied entries preserve input order.

    ### Boundary & Interpretation Rules
    * **Defensive Scope Only**: Performs catalog modeling and prioritization; no target exploitation or network port scanning.
    * **Vendor Counts $\\neq$ Risk**: Vendor counts describe catalog presence and reporting maturity, not vendor security or organizational exposure.
    * **Ransomware Unknown**: Indicates unconfirmed campaign use, not confirmed absence of ransomware danger.
    """)
