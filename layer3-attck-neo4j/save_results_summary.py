"""
Saves a reproducible results artefact for the Figure 6 (ATT&CK shared-
telemetry co-occurrence) design choice: the threshold sensitivity sweep
(cap = 20..3) and the 16 connected components at the chosen cap=10, each
with its driving DataComponent(s) and member Technique IDs/names. Mirrors
the project's existing convention of saving a results/*.json artefact
behind any numeric claim in main.tex (see experiment3_window_results.json).
"""
import csv
import json
from collections import defaultdict
import os
from pathlib import Path

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
dc = load("data_components.csv")[1:]
dc_name = {r[0]: r[1] for r in dc}
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

total_possible = 697 * 696 // 2
sweep = []
for cap in [20, 15, 10, 8, 6, 5, 4, 3]:
    pairs = set()
    for dcid, techs in dc_to_techs.items():
        if len(techs) > cap:
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
    sweep.append({
        "cap": cap,
        "n_pairs": len(pairs),
        "pct_of_all_pairs": round(100 * len(pairs) / total_possible, 3),
        "n_techniques_connected": len(connected),
    })

# uncapped sanity point (cap=697, i.e. no filtering) for the "why cap at all" claim
pairs_unfiltered = set()
for dcid, techs in dc_to_techs.items():
    techs = list(techs)
    for i in range(len(techs)):
        for j in range(i + 1, len(techs)):
            a, b = sorted([techs[i], techs[j]])
            pairs_unfiltered.add((a, b))

top_dcs = sorted(((dcid, len(techs)) for dcid, techs in dc_to_techs.items()),
                  key=lambda x: -x[1])[:5]

CAP = 10
pairs = set()
for dcid, techs in dc_to_techs.items():
    if len(techs) > CAP:
        continue
    techs = list(techs)
    for i in range(len(techs)):
        for j in range(i + 1, len(techs)):
            a, b = sorted([techs[i], techs[j]])
            pairs.add((a, b))
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

comp_summaries = []
for comp in components:
    dcs_in_comp = set()
    for a, b in pairs:
        if a in comp and b in comp:
            for dcid, techs in dc_to_techs.items():
                if len(techs) <= CAP and a in techs and b in techs:
                    dcs_in_comp.add(dcid)
    comp_summaries.append({
        "size": len(comp),
        "driving_data_components": sorted(dc_name.get(d, d) for d in dcs_in_comp),
        "technique_ids": sorted(comp),
        "technique_names": {t: tech_name.get(t, "?") for t in sorted(comp)},
    })

result = {
    "method": "Two Techniques are connected if their DetectionStrategy's "
              "Analytics jointly rely on >=1 shared DataComponent used by "
              "<= CAP Techniques project-wide (rare/specific telemetry "
              "only -- generic DataComponents like Process Creation, used "
              "by 455/697 = 65.3% of Techniques, are excluded by design).",
    "data_source": "layer3-attck-neo4j/data/csv/*.csv (same CSVs that "
                    "feed the live Neo4j instance; counts cross-checked "
                    "against Table 7 / kg_schema.dot before use).",
    "top_5_most_common_data_components": [
        {"name": dc_name.get(d, d), "n_techniques": n, "pct_of_697": round(100 * n / 697, 1)}
        for d, n in top_dcs
    ],
    "unfiltered_pair_count_if_no_cap": {
        "n_pairs": len(pairs_unfiltered),
        "pct_of_all_pairs": round(100 * len(pairs_unfiltered) / total_possible, 1),
        "note": "This is why a cap is necessary -- an unfiltered "
                "co-occurrence graph connects the majority of all "
                "possible Technique pairs and is unreadable.",
    },
    "threshold_sensitivity_sweep": sweep,
    "chosen_cap": CAP,
    "chosen_cap_is_a_design_choice_not_a_statistical_threshold": True,
    "n_components_at_chosen_cap": len(components),
    "components_at_chosen_cap": comp_summaries,
}

out_path = OUT / "attck_cooccurrence_topology_results.json"
out_path.write_text(json.dumps(result, indent=2))
print(f"Wrote {out_path}")
print(f"Sweep: {sweep}")
print(f"Unfiltered: {result['unfiltered_pair_count_if_no_cap']}")
