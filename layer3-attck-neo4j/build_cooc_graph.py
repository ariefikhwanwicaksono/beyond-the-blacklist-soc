"""
Alternative candidate: Technique co-occurrence graph via SHARED, relatively
RARE DataComponents (cap = max techniques touching that DataComponent to be
included -- generic/ubiquitous telemetry like "Process Creation" (touches
65.3% of all 697 techniques) is excluded on purpose, since including it
makes 53.7% of all possible technique pairs connect, i.e. an unreadable
near-complete graph -- confirmed by direct count on the project's own CSVs
before building this).

Edge: Technique A -- Technique B if their DetectionStrategy's Analytics
jointly rely on at least one DataComponent used by <= CAP techniques
project-wide. This is a real structural signal (shared reliance on uncommon
telemetry), not decoration, and not just a redraw of the already-explicit
SUBTECHNIQUE_OF parent/child column.
"""
import csv
from collections import defaultdict
import os
from pathlib import Path

CAP = 10
# CSV files produced by parse_attck.py; override with env ATTCK_CSV_DIR. (Previously an absolute path
# of the original analysis environment, "/mnt/user-data/uploads/..." -- same CSV content.)
CSV_DIR = Path(os.environ.get("ATTCK_CSV_DIR", Path(__file__).resolve().parent / "data" / "csv"))
OUT = Path(__file__).resolve().parent


def load(fn):
    with open(CSV_DIR / fn, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


techniques = load("techniques.csv")[1:]
detects = load("detects.csv")[1:]
dsa = load("detection_strategy_analytic.csv")[1:]
adc = load("analytic_datacomponent.csv")[1:]
tactics = load("technique_tactic.csv")[1:]

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

# primary tactic per technique (first one listed) -- used only for color
tech_primary_tactic = {}
for t, tac in tactics:
    tech_primary_tactic.setdefault(t, tac)

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

print(f"CAP={CAP}: {len(pairs)} unique pairs, {len(connected)} distinct techniques")

# color by top-level vs sub-technique (consistent with the project palette)
COLOR_TOP = "#2a78d6"
COLOR_TOP_STROKE = "#13467f"
COLOR_SUB = "#eb6834"
COLOR_SUB_STROKE = "#9c3f1b"

lines = ["graph attck_cooc {"]
lines.append('  bgcolor="white";')
lines.append('  outputorder=edgesfirst;')
lines.append('  node [shape=circle, style=filled, fixedsize=true, label="", penwidth=0.6, width=0.09, height=0.09];')
lines.append('  edge [color="#b9b9c0", penwidth=0.6];')

for t in connected:
    nid = t.replace(".", "_").replace("-", "_")
    if is_sub[t]:
        fill, stroke = COLOR_SUB, COLOR_SUB_STROKE
    else:
        fill, stroke = COLOR_TOP, COLOR_TOP_STROKE
    lines.append(f'  {nid} [fillcolor="{fill}", color="{stroke}"];')

for a, b in pairs:
    na = a.replace(".", "_").replace("-", "_")
    nb = b.replace(".", "_").replace("-", "_")
    lines.append(f"  {na} -- {nb};")

lines.append("}")
out_path = OUT / f"attck_cooc_cap{CAP}.dot"
out_path.write_text("\n".join(lines))
print(f"Wrote {out_path}")
