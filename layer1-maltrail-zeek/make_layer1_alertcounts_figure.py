"""
Figure 5 of the paper draft: Layer 1 (Maltrail) alert counts across the full
pilot + supplementary corpus -- the six Table 5 entries
(results/pilot_summary_layer1.csv) plus the two CTU-Normal benign hosts
run later (ctu_normal32=123, ctu_normal33=13; see README.md "Bug pin
trails.csv..." section and main.tex Discussion/Limitations). No numbers are
hand-typed beyond those two, which are not in pilot_summary_layer1.csv
(that sensor run was never added to the CSV) but are directly reported
and sourced in README.md / main.tex.

Palette: validated project pair (blue #2a78d6 / orange #eb6834), same two
hex values already used for Figure 2 (bc_distribution.pdf) -- reused here
as a fresh categorical pair (malware vs benign ground truth) with this
figure's own legend.

Usage: run standalone. Writes layer1_alertcounts.pdf next to this script.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = Path(__file__).resolve().parent

# (display_label, n_alerts, ground_truth, source)
rows = [
    ("zeus", 5697, "malware", "Table 5"),
    ("tinba", 10902, "malware", "Table 5"),
    ("dridex", 0, "malware", "Table 5"),
    ("iot23_capture1", 5, "malware", "Table 5"),
    ("bittorrent", 0, "benign", "Table 5"),
    ("skype", 0, "benign", "Table 5"),
    ("ctu_normal32", 123, "benign", "\xa7Discussion"),
    ("ctu_normal33", 13, "benign", "\xa7Discussion"),
]

plt.rcParams.update({
    "font.size": 9,
    "font.family": "serif",
    "axes.edgecolor": "#52514e",
    "axes.labelcolor": "#0b0b0b",
    "text.color": "#0b0b0b",
    "xtick.color": "#52514e",
    "ytick.color": "#52514e",
})

fig, ax = plt.subplots(figsize=(7.0, 3.0), dpi=300)

color_malware = "#2a78d6"
color_benign = "#eb6834"

# positions: malware group at 0-3, gap, benign group at 4.6-7.6
xpos = [0, 1, 2, 3, 4.6, 5.6, 6.6, 7.6]
labels = [r[0] for r in rows]
heights = [r[1] for r in rows]
colors = [color_malware if r[2] == "malware" else color_benign for r in rows]

bars = ax.bar(xpos, heights, color=colors, width=0.7, edgecolor="white", linewidth=0.5, zorder=3)

# group divider
ax.axvline(3.8, color="#d9d8d2", linewidth=1.0, zorder=1)

# direct value labels on every bar (several are visually near-zero)
for x, h in zip(xpos, heights):
    ax.text(x, h + max(heights) * 0.015, f"{h:,}", ha="center", va="bottom", fontsize=7.5, color="#0b0b0b")

ax.set_xticks(xpos)
ax.set_xticklabels(labels, fontsize=7.5, rotation=20, ha="right")
ax.set_ylabel("Maltrail alert lines\n(sensor.py)", fontsize=8.5)
ax.set_ylim(0, max(heights) * 1.17)
ax.set_xlim(-0.7, 8.3)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.yaxis.grid(True, color="#e5e4df", linewidth=0.6, zorder=0)
ax.set_axisbelow(True)

# group labels, placed just under the axis title area via the axes transform
# (independent of data scale, so they never collide with bars/labels)
ax.text(0.244, -0.30, "malware-labelled", transform=ax.transAxes, ha="center",
        fontsize=8, color="#52514e", style="italic")
ax.text(0.756, -0.30, "benign-labelled", transform=ax.transAxes, ha="center",
        fontsize=8, color="#52514e", style="italic")

# callout on the two CTU-Normal bars (the new, non-zero benign finding)
for cx, ch in [(6.6, 123), (7.6, 13)]:
    ax.annotate(
        "", xy=(cx, ch + max(heights) * 0.02), xycoords="data",
        xytext=(7.1, max(heights) * 0.46), textcoords="data",
        arrowprops=dict(arrowstyle="-", color="#9c3f1b", linewidth=0.8, shrinkA=2, shrinkB=4),
    )
ax.text(7.1, max(heights) * 0.49, "ad-tech/TDS blacklist\nmatches, DNS-only\n(Discussion, \xa74)",
        ha="center", va="bottom", fontsize=7, color="#52514e")

legend_elems = [
    Patch(facecolor=color_malware, edgecolor="white", label="Malware-labelled host"),
    Patch(facecolor=color_benign, edgecolor="white", label="Benign-labelled host"),
]
ax.legend(handles=legend_elems, loc="lower left", bbox_to_anchor=(0.0, 1.01),
          fontsize=7.5, frameon=False, ncol=2)

plt.tight_layout()
out_path = HERE / "layer1_alertcounts.pdf"
plt.savefig(out_path, bbox_inches="tight")
print(f"Saved: {out_path}")
