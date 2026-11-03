"""
Regenerates Figure 2 of the paper draft (pooled behaviour-class distribution,
379 windows / 8 hosts) directly from bc_results.json -- the saved output of
layer2-behavior-features/compute_behavior_classes.py. No numbers
are hand-typed here; everything plotted is read from that file.

Usage: run from within layer2-behavior-features/ (so the relative
path to bc_results.json resolves), or pass an explicit path as argv[1].
Writes bc_distribution.pdf next to this script.
"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = Path(__file__).resolve().parent
json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "bc_results.json"
data = json.loads(json_path.read_text())

pooled_pct = {int(k): v for k, v in data["pooled_bc_distribution_pct"].items()}
rare_bcs = set(data["rare_bcs"])
threshold = data["rare_bc_threshold"] * 100
total_windows = data["total_windows"]

all_bcs = list(range(27))
heights = [pooled_pct.get(bc, 0.0) for bc in all_bcs]
colors = ["#eb6834" if bc in rare_bcs else ("#2a78d6" if pooled_pct.get(bc, 0.0) > 0 else "#d9d8d2") for bc in all_bcs]

plt.rcParams.update({
    "font.size": 9,
    "font.family": "serif",
    "axes.edgecolor": "#52514e",
    "axes.labelcolor": "#0b0b0b",
    "text.color": "#0b0b0b",
    "xtick.color": "#52514e",
    "ytick.color": "#52514e",
})

fig, ax = plt.subplots(figsize=(7.0, 2.6), dpi=300)

bars = ax.bar(all_bcs, heights, color=colors, width=0.7, edgecolor="white", linewidth=0.4, zorder=3)
for bc, bar in zip(all_bcs, bars):
    if bc in rare_bcs:
        bar.set_hatch("///")
        bar.set_edgecolor("#9c3f1b")

ax.axhline(threshold, color="#52514e", linewidth=0.9, linestyle="--", zorder=2)
ax.text(13.5, threshold + 2.0, f"{threshold:.0f}% rare threshold", fontsize=7.5, color="#52514e", ha="center")

ax.set_xlim(-0.8, 26.8)
ax.set_xticks(all_bcs)
ax.set_xticklabels([str(b) for b in all_bcs], fontsize=7)
ax.set_xlabel("Behaviour class (BC = $9L(X)+3L(Y)+L(Z)$, $X$=srcPort, $Y$=dstPort, $Z$=dstIP)", fontsize=8.5)
ax.set_ylabel(f"Share of {total_windows} pooled\nwindows (%)", fontsize=8.5)
ax.set_ylim(0, 72)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.yaxis.grid(True, color="#e5e4df", linewidth=0.6, zorder=0)
ax.set_axisbelow(True)

# Direct-label only the three dominant classes (>10% share); the rest are
# legible from the table in the paper, and labelling all 9 would clutter.
for bc, h in pooled_pct.items():
    if h >= 10:
        ax.text(bc, h + 1.0, f"{h:.1f}%", ha="center", fontsize=7, color="#0b0b0b")

n_occupied = sum(1 for h in heights if h > 0)
ax.text(0.01, 0.95, f"{n_occupied}/27 classes occupied", transform=ax.transAxes,
        fontsize=7.5, color="#52514e", va="top", ha="left")

legend_elems = [
    Patch(facecolor="#2a78d6", edgecolor="white", label=f"Common ($\\geq${threshold:.0f}% of windows)"),
    Patch(facecolor="#eb6834", edgecolor="#9c3f1b", hatch="///", label=f"Rare ($<${threshold:.0f}% of windows)"),
]
ax.legend(handles=legend_elems, loc="upper left", fontsize=7.5, frameon=False, bbox_to_anchor=(0.30, 1.03))

plt.tight_layout()
out_path = HERE / "bc_distribution.pdf"
plt.savefig(out_path, bbox_inches="tight")
print(f"Saved: {out_path}")
