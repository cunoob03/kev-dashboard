"""Four headless Matplotlib charts for the selected records."""

from collections import Counter
from datetime import date
from pathlib import Path
from textwrap import fill

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .counters import count_by_vendor
from . import config

BLUE = "#3979a6"
RED = "#bf4545"
ORANGE = "#dd982d"
GREEN = "#438b69"


def _chart(title, catalog_info):
    fig, ax = plt.subplots(figsize=(11, 7))
    fig.set_facecolor("#f6f8fb")
    ax.set_facecolor("#f6f8fb")
    fig.suptitle(title, x=0.08, y=0.96, ha="left", fontsize=17, fontweight="bold")
    filters = "; ".join(catalog_info.get("applied_filters", [])) or "All records"
    provenance = (
        f"Catalog {catalog_info.get('catalog_version', 'Unknown')} | "
        f"Reference {catalog_info.get('reference_date', 'Unknown')} | "
        f"Downloaded {catalog_info.get('download_date') or 'Unknown'}"
    )
    fig.text(0.08, 0.90, fill(provenance, 110) + "\n" + fill(f"Selection: {filters}", 110),
             va="top", fontsize=9, color="#435268")
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)
    ax.grid(axis="y", alpha=0.15)
    return fig, ax


def _save(fig, output_path, note):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.text(0.08, 0.025, fill(note, 125), fontsize=9, color="#435268")
    fig.tight_layout(rect=(0.02, 0.08, 0.98, 0.80))
    try:
        fig.savefig(path, dpi=150, facecolor=fig.get_facecolor())
    finally:
        plt.close(fig)


def _empty(ax, message="No matching records"):
    ax.text(0.5, 0.5, message, transform=ax.transAxes, ha="center", va="center")
    ax.set_xticks([])
    ax.set_yticks([])


def plot_top_vendors(counts_dict, catalog_info, output_path, top_n=10):
    if top_n < 1:
        raise ValueError("top_n must be positive")
    items = sorted(counts_dict.items(), key=lambda item: (-item[1], item[0]))[:top_n]
    fig, ax = _chart(f"Top {top_n} vendors — counts ≠ risk", catalog_info)
    if items:
        names, counts = zip(*items)
        bars = ax.barh([fill(name, 28) for name in names], counts, color=BLUE)
        ax.bar_label(bars, padding=5)
        ax.invert_yaxis()
        ax.set_xlim(0, max(counts) * 1.18)
        ax.set_xlabel("KEV entries")
    else:
        _empty(ax)
    _save(fig, output_path, "Counts reflect catalog presence, not vendor security.")


def plot_due_status(worklist, catalog_info, output_path):
    stats = worklist.summary_stats()
    info = dict(catalog_info)
    info["reference_date"] = worklist.reference_date.isoformat()
    fig, ax = _chart("Deadlines at the reference date", info)
    counts = [stats[key] for key in ("overdue_count", "due_soon_count", "not_yet_due_count")]
    bars = ax.bar(["Overdue\n< 0 days", f"Due soon\n0–{config.DUE_SOON_DAYS} days",
                   f"Not yet due\n> {config.DUE_SOON_DAYS} days"],
                  counts, color=[RED, ORANGE, GREEN])
    ax.bar_label(bars, padding=5)
    ax.set_ylim(0, max(max(counts), 1) * 1.18)
    ax.set_ylabel("KEV entries")
    _save(fig, output_path,
          f"No due date: {stats['no_due_date_count']} (excluded from bars). "
          "Catalog deadlines do not establish an organization's remediation status.")


def plot_monthly_trend(records, catalog_info, output_path):
    counts = Counter(
        (record.date_added.year, record.date_added.month)
        for record in records if record.date_added is not None
    )
    fig, ax = _chart("KEV additions by month", catalog_info)
    if counts:
        start, end = min(counts), max(counts)
        current = date(*start, 1)
        months = []
        while (current.year, current.month) <= end:
            months.append((current.year, current.month))
            if (current.year, current.month) == end:
                break
            current = date(current.year + current.month // 12, current.month % 12 + 1, 1)
        positions = np.arange(len(months))
        ax.bar(positions, [counts[month] for month in months], color=BLUE)
        step = max(1, (len(months) + 11) // 12)
        ticks = list(range(0, len(months), step))
        if ticks[-1] != len(months) - 1:
            ticks.append(len(months) - 1)
        ax.set_xticks(ticks, [f"{months[i][0]}-{months[i][1]:02d}" for i in ticks],
                      rotation=45, ha="right")
        ax.set_ylabel("Entries added")
        ax.set_xlabel("Month added to the catalog")
    else:
        _empty(ax, "No matching records with date_added")
    missing = sum(record.date_added is None for record in records)
    _save(fig, output_path,
          f"Selected records only; missing date_added excluded: {missing}. "
          "Zero-count months are included. Additions are not dates of first exploitation.")


def plot_ransomware_by_vendor(records, catalog_info, output_path, top_n=10):
    if top_n < 1:
        raise ValueError("top_n must be positive")
    vendors = list(count_by_vendor(records))[:top_n]
    counts = Counter(
        (r.vendor_project or "(missing vendor)", (r.known_ransomware_campaign_use or "").casefold())
        for r in records
    )
    fig, ax = _chart(f"Ransomware use — top {top_n} vendors", catalog_info)
    if vendors:
        positions = np.arange(len(vendors))
        for offset, label, color in [(-0.2, "Known", RED), (0.2, "Unknown", BLUE)]:
            bars = ax.bar(positions + offset,
                          [counts[vendor, label.casefold()] for vendor in vendors],
                          width=0.4, label=label, color=color)
            ax.bar_label(bars, padding=3, fontsize=8)
        ax.set_xticks(positions, [fill(vendor, 18) for vendor in vendors],
                      rotation=35, ha="right")
        ax.set_ylabel("KEV entries")
        ax.margins(y=0.18)
        ax.legend()
    else:
        _empty(ax)
    other = sum(
        (r.vendor_project or "(missing vendor)") in vendors
        and (r.known_ransomware_campaign_use or "").casefold() not in {"known", "unknown"}
        for r in records
    )
    _save(fig, output_path,
          f"Unknown means unconfirmed, not absent. Other/missing values excluded: {other}. "
          "Counts reflect catalog presence, not vendor security.")
