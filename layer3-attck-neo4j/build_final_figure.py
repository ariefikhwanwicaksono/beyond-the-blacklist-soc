"""
Final Figure 6: ATT&CK Technique shared-telemetry co-occurrence topology.

Pipeline:
1. Rebuild the cap<=10 co-occurrence graph from the verified CSVs (same
   construction as attck_cooc_cap10.dot / build_cooc_graph.py).
2. Lay it out with Graphviz sfdp (-Tplain to get x,y per node).
3. Redraw with matplotlib (project's established serif/matplotlib style,
   same as Figure 2/bc_distribution and Figure 5/layer1_alertcounts) so we
   get full control over cluster highlight ellipses + labels, which
   Graphviz's own cluster mechanism does not support well under sfdp.
4. Draw translucent highlight ellipses + text labels behind 3 of the
   cleanest, most tactically-legible connected components (identified by
   manual inspection of technique names in each component, cross-checked
   against techniques.csv -- not invented):
     - AD / Kerberos credential-access techniques (21 techniques)
     - Infrastructure acquisition (10 techniques)
     - Capability development (8 techniques)
   The remaining components (including the large 47-node cloud/container
   component) are shown unlabeled/uncalled-out -- honest about not every
   cluster being individually legible at this scale.

Node color: top-level Technique (blue #2a78d6) vs sub-technique
(orange #eb6834) -- same validated pair used in Figures 2 and 5.
"""
import csv
import subprocess
from collections import defaultdict
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, Patch
from matplotlib.lines import Line2D

# CSV files produced by parse_attck.py; override with env ATTCK_CSV_DIR. (Previously an absolute path
# of the original analysis environment, "/mnt/user-data/uploads/..." -- same CSV content.)
CSV_DIR = Path(os.environ.get("ATTCK_CSV_DIR", Path(__file__).resolve().parent / "data" / "csv"))
HERE = Path(__file__).resolve().parent
CAP = 10


def load(fn):
    with open(CSV_DIR / fn, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


techniques = load("techniques.csv")[1:]
detects = load("detects.csv")[1:]
dsa = load("detection_strategy_analytic.csv")[1:]
adc = load("analytic_datacomponent.csv")[1:]

tech_name = {r[0]: r[1] for r in techniques}
is_sub = {r[0]: r[2].strip().lower() in ("true", "1", "yes") for r in techniques}
tech_to_ds = {t: d for d, t in detects}
ds_to_analytics = defaultdict(list)
for d, a in dsa:
    ds_to_analytics[d].append(a)
analytic_to_dcs = defaultdict(set)
for a, dcid, *_ in adc:
    analytic_to_dcs[a].add(dcid)
tech_to_dcs = {}
for t, d in tech_to_ds.items():
    dcs = set()
    for a in ds_to_analytics.get(d, []):
        dcs |= analytic_to_dcs.get(a, set())
    tech_to_dcs[t] = dcs

dc_to_techs = defaultdict(set)
for t, dcs in tech_to_dcs.items():
    for dcid in dcs:
        dc_to_techs[dcid].add(t)

pairs = set()
for dcid, techs in dc_to_techs.items():
    if len(techs) > CAP:
        continue
    techs = list(techs)
    for i in range(len(techs)):
        for j in range(i + 1, len(techs)):
            a, b = sorted([techs[i], techs[j]])
            pairs.add((a, b))

connected = set()
for a, b in pairs:
    connected.add(a)
    connected.add(b)

# ---- connected components (for identifying the 3 labeled clusters) ----
adj = defaultdict(set)
for a, b in pairs:
    adj[a].add(b)
    adj[b].add(a)
visited = set()
components = []
for node in adj:
    if node in visited:
        continue
    stack = [node]
    comp = set()
    while stack:
        n = stack.pop()
        if n in comp:
            continue
        comp.add(n)
        visited.add(n)
        for nb in adj[n]:
            if nb not in comp:
                stack.append(nb)
    components.append(comp)
components.sort(key=len, reverse=True)

# find the component containing a known anchor technique id (anchors chosen
# from the manual inspection output above: Kerberoasting / Acquire
# Infrastructure: Domains / Develop Capabilities: Malware)
def comp_containing(tid):
    for c in components:
        if tid in c:
            return c
    return None

comp_ad = comp_containing("T1558.003")
comp_infra = comp_containing("T1583.001")
comp_capdev = comp_containing("T1587.001")

print("AD/Kerberos component size:", len(comp_ad) if comp_ad else None)
print("Infra acquisition component size:", len(comp_infra) if comp_infra else None)
print("Capability dev component size:", len(comp_capdev) if comp_capdev else None)

# ---- write dot, layout with sfdp, parse plain-text coordinates ----
dot_lines = ["graph g {"]
for t in connected:
    nid = t.replace(".", "_").replace("-", "_")
    dot_lines.append(f'  {nid};')
for a, b in pairs:
    na = a.replace(".", "_").replace("-", "_")
    nb = b.replace(".", "_").replace("-", "_")
    dot_lines.append(f"  {na} -- {nb};")
dot_lines.append("}")
dot_path = HERE / "final_layout.dot"
dot_path.write_text("\n".join(dot_lines))

plain = subprocess.run(
    ["sfdp", "-Tplain", "-Goverlap=prism", "-Gsep=+6", "-GK=0.7", str(dot_path)],
    capture_output=True, text=True, check=True,
).stdout
id_to_tech = {t.replace(".", "_").replace("-", "_"): t for t in connected}
pos = {}
scale_w = scale_h = 1.0
for line in plain.splitlines():
    parts = line.split()
    if not parts:
        continue
    if parts[0] == "graph":
        scale_w, scale_h = float(parts[2]), float(parts[3])
    elif parts[0] == "node":
        nid, x, y = parts[1], float(parts[2]), float(parts[3])
        if nid in id_to_tech:
            pos[id_to_tech[nid]] = (x, y)

print(f"Parsed {len(pos)} node positions")

# ---- nudge the 3 highlighted components outward so their callouts don't
# visually bleed into neighbouring, unlabeled cliques (a rigid translation
# of each component as a whole -- does not alter which edges exist, only
# where that subgraph sits in the printed layout) ----
_all_xs = [p[0] for p in pos.values()]
_all_ys = [p[1] for p in pos.values()]
_midx = (min(_all_xs) + max(_all_xs)) / 2
_midy = (min(_all_ys) + max(_all_ys)) / 2


def nudge_component(comp, factor=0.22):
    cxs = [pos[t][0] for t in comp]
    cys = [pos[t][1] for t in comp]
    ccx, ccy = sum(cxs) / len(cxs), sum(cys) / len(cys)
    vx, vy = ccx - _midx, ccy - _midy
    norm = max((vx ** 2 + vy ** 2) ** 0.5, 1e-6)
    ux, uy = vx / norm, vy / norm
    dx = ux * (max(_all_xs) - min(_all_xs)) * factor
    dy = uy * (max(_all_ys) - min(_all_ys)) * factor
    for t in comp:
        x, y = pos[t]
        pos[t] = (x + dx, y + dy)


nudge_component(comp_ad, factor=0.30)
nudge_component(comp_infra, factor=0.26)
nudge_component(comp_capdev, factor=0.24)

# ---- draw with matplotlib ----
plt.rcParams.update({
    "font.size": 9, "font.family": "serif",
    "text.color": "#0b0b0b",
})

fig, ax = plt.subplots(figsize=(7.2, 5.6), dpi=300)

COLOR_TOP = "#2a78d6"
COLOR_SUB = "#eb6834"

for a, b in pairs:
    xa, ya = pos[a]
    xb, yb = pos[b]
    ax.plot([xa, xb], [ya, yb], color="#c7c7cd", linewidth=0.45, zorder=1, solid_capstyle="round")

xs = [pos[t][0] for t in connected]
ys = [pos[t][1] for t in connected]
colors = [COLOR_SUB if is_sub[t] else COLOR_TOP for t in connected]
ax.scatter(xs, ys, s=11, c=colors, edgecolors="white", linewidths=0.25, zorder=3)

span_x = max(xs) - min(xs)
span_y = max(ys) - min(ys)


def draw_cluster_label(comp, text, label_xy, fontsize=6.6, color="#52514e", ellipse=True):
    cxs = [pos[t][0] for t in comp]
    cys = [pos[t][1] for t in comp]
    cx, cy = sum(cxs) / len(cxs), sum(cys) / len(cys)
    bbox_w, bbox_h = max(cxs) - min(cxs), max(cys) - min(cys)
    # only draw the highlight ellipse when the component is actually
    # spatially compact after layout -- a sparse/spread-out component
    # (bbox close to the whole plot's extent) would need an ellipse so
    # large it stops meaning anything, so skip it and label only.
    if ellipse and bbox_w < span_x * 0.4 and bbox_h < span_y * 0.4:
        pad_x = max(bbox_w * 0.35, span_x * 0.02)
        pad_y = max(bbox_h * 0.35, span_y * 0.02)
        w = bbox_w + 2 * pad_x
        h = bbox_h + 2 * pad_y
        ell = Ellipse((cx, cy), w, h, facecolor="#2a78d6", alpha=0.07,
                      edgecolor="#2a78d6", linewidth=0.7, linestyle="--", zorder=0)
        ax.add_patch(ell)
    lx, ly = label_xy
    ax.annotate(text, xy=(cx, cy), xytext=(lx, ly),
                fontsize=fontsize, color=color, ha="center", va="center",
                style="italic",
                arrowprops=dict(arrowstyle="-", color="#9A9A9A", linewidth=0.5,
                                 shrinkA=2, shrinkB=2),
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#d9d8d2", lw=0.5))


xmin, xmax = min(xs), max(xs)
ymin, ymax = min(ys), max(ys)
midx, midy = (xmin + xmax) / 2, (ymin + ymax) / 2


def radial_label_xy(comp, radius_x, radius_y):
    """Place the label outward along the line from the plot centre through
    this component's own centroid, so the leader line points radially
    outward instead of crossing the whole figure."""
    cxs = [pos[t][0] for t in comp]
    cys = [pos[t][1] for t in comp]
    ccx, ccy = sum(cxs) / len(cxs), sum(cys) / len(cys)
    vx, vy = ccx - midx, ccy - midy
    norm = max((vx ** 2 + vy ** 2) ** 0.5, 1e-6)
    ux, uy = vx / norm, vy / norm
    return ccx + ux * radius_x, ccy + uy * radius_y


if comp_ad:
    draw_cluster_label(comp_ad,
                        "AD / Kerberos credential techniques (21)\n"
                        "spans Credential Access, Lateral\n"
                        "Movement, Discovery tactics",
                        label_xy=radial_label_xy(comp_ad, span_x * 0.34, span_y * 0.30))
if comp_infra:
    draw_cluster_label(comp_infra, "Infrastructure\nacquisition (10)",
                        label_xy=radial_label_xy(comp_infra, span_x * 0.30, span_y * 0.22))
if comp_capdev:
    draw_cluster_label(comp_capdev, "Capability\ndevelopment (8)",
                        label_xy=radial_label_xy(comp_capdev, span_x * 0.28, span_y * 0.22))

# recompute data bounds AFTER the nudge (xs/ys captured before nudging
# above are stale once components move)
xs = [pos[t][0] for t in connected]
ys = [pos[t][1] for t in connected]
ax.set_xlim(min(xs) - span_x * 0.30, max(xs) + span_x * 0.32)
ax.set_ylim(min(ys) - span_y * 0.30, max(ys) + span_y * 0.26)
ax.set_aspect("equal")
ax.axis("off")

legend_elems = [
    Line2D([0], [0], marker="o", color="none", markerfacecolor=COLOR_TOP,
           markeredgecolor="white", markersize=6, label="Top-level Technique"),
    Line2D([0], [0], marker="o", color="none", markerfacecolor=COLOR_SUB,
           markeredgecolor="white", markersize=6, label="Sub-technique"),
]
ax.legend(handles=legend_elems, loc="upper left", bbox_to_anchor=(0.0, 0.04),
          fontsize=7, frameon=False, ncol=2)

plt.tight_layout()
out_path = HERE / "attck_cooc_final.pdf"
plt.savefig(out_path, bbox_inches="tight")
out_png = HERE / "attck_cooc_final.png"
plt.savefig(out_png, bbox_inches="tight", dpi=200)
print(f"Saved: {out_path}")
