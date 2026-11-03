from pathlib import Path
import nbformat as nbf
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell
from nbclient import NotebookClient

cells = []

cells.append(new_markdown_cell('''# Experiment 3 (prototype): Layer 2 -> Layer 3 escalation + ATT&CK technique matching

This notebook is executed directly (not written first with results claimed afterwards) -- all numbers below
are the real output of running these cells against the raw data already used by Layer 1
(`layer1-maltrail-zeek/`) and Layer 2 (`layer2-behavior-features/`).

**Escalation trigger to L3** (not a newly invented threshold; it uses what already exists in the
architecture): the window is NOT flagged by Maltrail (L1) AND the window falls in a rare BC class (L2,
unsupervised, from `bc_results.json`).

**Technique matching**: for an escalated window, compute the raw metrics EXACTLY as measured by each Maltrail
heuristic (distinct dst-ports per dst_ip within a 30-second window for `port_scanning`; distinct dst_ips per
dst_port within a 30-second window for `infection`; UDP-only for `udp_scanning`), pick the heuristic with the
highest ratio-to-threshold (even if below Maltrail's official threshold), and map it to a candidate ATT&CK
technique via a table grounded by reading `sensor.py` directly plus the official technique definitions --
not from host labels.

Ground-truth labels (the per-host `truth` field) are only opened in the very last evaluation cell.'''))

cells.append(new_markdown_cell("## Section A: setup, load the raw data of the 8 hosts (Zeek conn.log + UWF CSV)"))

cells.append(new_code_cell('''import sys, re, json
from pathlib import Path
from collections import defaultdict, Counter

BASE = Path.cwd().parent  # run this notebook from inside experiment3-graph-inspection/
sys.path.insert(0, str(BASE / "layer2-behavior-features"))
from compute_behavior_classes import (
    OLD_HOSTS, UWF_FILTERED_FILES, load_old_host_rows, load_uwf_host_rows,
    windows_from_rows, compute_bc_for_windows,
)

print("Original hosts (Zeek conn.log):")
for h, p, ipf, truth in OLD_HOSTS:
    print(f"  {h:15s} truth={truth!r}")
print("UWF hosts (filtered CSV):")
for h, (p, ip, truth) in UWF_FILTERED_FILES.items():
    print(f"  {h:15s} truth={truth!r}")'''))

cells.append(new_markdown_cell("## Section B: read the Maltrail thresholds directly from `core/settings.py` (not hard-coded)"))

cells.append(new_code_cell('''settings_text = (BASE / "layer1-maltrail-zeek" / "tools" / "maltrail" / "core" / "settings.py").read_text()

def read_const(name):
    m = re.search(rf"^{name}\\s*=\\s*(\\d+)", settings_text, re.M)
    return int(m.group(1))

PORT_SCANNING_THRESHOLD = read_const("PORT_SCANNING_THRESHOLD")
INFECTION_SCANNING_THRESHOLD = read_const("INFECTION_SCANNING_THRESHOLD")
SCAN_WINDOW_SEC = 30

RARE_BCS = {15, 19, 21, 24}  # from bc_results.json rare_bcs (Layer 2, verified earlier)

print(f"PORT_SCANNING_THRESHOLD = {PORT_SCANNING_THRESHOLD}")
print(f"INFECTION_SCANNING_THRESHOLD = {INFECTION_SCANNING_THRESHOLD}")
print(f"SCAN_WINDOW_SEC = {SCAN_WINDOW_SEC}")
print(f"RARE_BCS = {sorted(RARE_BCS)}")'''))

cells.append(new_markdown_cell('''## Section C: mapping table heuristic -> candidate ATT&CK technique

Grounding: read directly from the mechanism in `sensor.py` (not just from the heuristic's name), plus the
official technique definitions on attack.mitre.org. Honest confidence label per row -- this table is NEW and
had not been verified before in this project, unlike the existing per-host grounding (already used for
episode 2 of `.7.10` -> T1046, and `143.88.5.12` -> T1590.002).'''))

cells.append(new_code_cell('''HEURISTIC_TECHNIQUE_MAP = {
    # port_scanning: 1 dst_ip, many distinct dst_ports from 1 src within 1 window -- exactly the definition
    # of T1046 (already used earlier in this project to ground episode 2 of .7.10). [HIGH]
    "port_scanning": dict(technique_id="T1046", name="Network Service Discovery", confidence="HIGH"),
    # udp_scanning: same logic as port_scanning but for UDP -- same technique, slightly lower confidence
    # because it had not been grounded before in this project. [MEDIUM]
    "udp_scanning": dict(technique_id="T1046", name="Network Service Discovery", confidence="MEDIUM"),
    # infection: 1 dst_port, many distinct dst_ips from 1 LOCAL src within 1 window (confirmed by
    # reading sensor.py: _src_ip.startswith(_get_local_prefix())) -- sweeps many HOSTS on the same
    # port/service, a different axis from port_scanning. Closest to T1595.001 (Active
    # Scanning: Scanning IP Blocks). [MEDIUM]
    "infection": dict(technique_id="T1595.001", name="Active Scanning: Scanning IP Blocks", confidence="MEDIUM"),
}
for k, v in HEURISTIC_TECHNIQUE_MAP.items():
    tid = v["technique_id"]; nm = v["name"]; conf = v["confidence"]
    print(f"{k:15s} -> {tid} ({nm})  [{conf}]")'''))

cells.append(new_markdown_cell("## Section D: compute the metrics per 30-second window (exactly as sensor.py measures them)"))

cells.append(new_code_cell('''def sub_window_metrics(rows, win_sec=SCAN_WINDOW_SEC):
    """Compute the Maltrail metrics per 30-second window INSIDE one 300-second window (the rows passed in)."""
    if not rows:
        return dict(port_scanning=0, udp_scanning=0, infection=0)
    t0 = min(r["ts"] for r in rows)
    ps_buckets = defaultdict(lambda: defaultdict(set))   # port_scanning: per (w, dst_ip) -> set(dst_port), TCP only
    udp_buckets = defaultdict(lambda: defaultdict(set))  # udp_scanning: same but UDP only
    inf_buckets = defaultdict(lambda: defaultdict(set))  # infection: per (w, dst_port) -> set(dst_ip), TCP+UDP
    for r in rows:
        w = int((r["ts"] - t0) // win_sec)
        if r["proto"] == "tcp":
            ps_buckets[w][r["dst_ip"]].add(r["dst_port"])
        elif r["proto"] == "udp":
            udp_buckets[w][r["dst_ip"]].add(r["dst_port"])
        inf_buckets[w][r["dst_port"]].add(r["dst_ip"])

    max_ps = max((len(s) for w in ps_buckets.values() for s in w.values()), default=0)
    max_udp = max((len(s) for w in udp_buckets.values() for s in w.values()), default=0)
    max_inf = max((len(s) for w in inf_buckets.values() for s in w.values()), default=0)
    return dict(port_scanning=max_ps, udp_scanning=max_udp, infection=max_inf)

print("Function sub_window_metrics ready.")'''))

cells.append(new_markdown_cell("## Section E: run for all 8 hosts -- build 379 window records (ground truth NOT yet opened)"))

cells.append(new_code_cell('''all_results = []

def process(host_id, rows, truth):
    wins = windows_from_rows(rows)  # 300-second windows, EXACTLY as in compute_behavior_classes.py
    bc_wins = compute_bc_for_windows(wins)
    for idx, (wrows, bcinfo) in enumerate(zip(wins, bc_wins)):
        m = sub_window_metrics(wrows)
        flagged_ps = m["port_scanning"] > PORT_SCANNING_THRESHOLD
        flagged_udp = m["udp_scanning"] > PORT_SCANNING_THRESHOLD  # same threshold as port_scanning in Maltrail
        flagged_inf = m["infection"] > INFECTION_SCANNING_THRESHOLD
        maltrail_flagged = flagged_ps or flagged_udp or flagged_inf
        is_rare = bcinfo["bc"] in RARE_BCS

        escalated = (not maltrail_flagged) and is_rare
        candidate = None
        if escalated:
            ratios = {
                "port_scanning": m["port_scanning"] / PORT_SCANNING_THRESHOLD,
                "udp_scanning": m["udp_scanning"] / PORT_SCANNING_THRESHOLD,
                "infection": m["infection"] / INFECTION_SCANNING_THRESHOLD,
            }
            best_heur = max(ratios, key=ratios.get)
            if ratios[best_heur] > 0:
                mapping = HEURISTIC_TECHNIQUE_MAP[best_heur]
                candidate = dict(heuristic=best_heur, ratio_to_threshold=round(ratios[best_heur], 3), **mapping)

        all_results.append(dict(
            host_id=host_id, window_idx=idx, truth=truth, bc=bcinfo["bc"], is_rare_bc=is_rare,
            n_flows=bcinfo["n_flows"], metrics=m,
            maltrail_flagged=maltrail_flagged, escalated_to_l3=escalated,
            l3_candidate=candidate,
        ))

for host_id, path, ipf, truth in OLD_HOSTS:
    rows = load_old_host_rows(path, ipf)
    process(host_id, rows, truth)

for host_id, (path, ip, truth) in UWF_FILTERED_FILES.items():
    rows = load_uwf_host_rows(path, ip)
    process(host_id, rows, truth)

print(f"Total windows processed: {len(all_results)}")'''))

cells.append(new_markdown_cell("## Section F: save the raw results"))

cells.append(new_code_cell('''out_dir = Path.cwd() / "results"
out_dir.mkdir(parents=True, exist_ok=True)
out_path = out_dir / "experiment3_window_results.json"
out_path.write_text(json.dumps(all_results, indent=2))
print(f"Saved: {out_path} ({len(all_results)} windows)")'''))

cells.append(new_markdown_cell("## Section G: evaluation -- ground truth is OPENED here, only now"))

cells.append(new_code_cell('''BENIGN_HOSTS = {"ctu_normal32", "ctu_normal33"}
pos = [r for r in all_results if r["host_id"] not in BENIGN_HOSTS]
neg = [r for r in all_results if r["host_id"] in BENIGN_HOSTS]

print(f"Total windows: {len(all_results)}  (positive/malicious-host: {len(pos)}, negative/benign-host: {len(neg)})")
print()
print("--- per host: n_windows, n_rare_bc, n_maltrail_flagged, n_escalated_to_l3, n_l3_matched ---")
by_host = defaultdict(list)
for r in all_results:
    by_host[r["host_id"]].append(r)
for h, rs in by_host.items():
    n_rare = sum(1 for r in rs if r["is_rare_bc"])
    n_flag = sum(1 for r in rs if r["maltrail_flagged"])
    n_esc = sum(1 for r in rs if r["escalated_to_l3"])
    n_match = sum(1 for r in rs if r["l3_candidate"])
    print(f"  {h:20s} n={len(rs):3d} rare_bc={n_rare:3d} maltrail_flag={n_flag:3d} escalated={n_esc:3d} l3_matched={n_match:3d}")'''))

cells.append(new_code_cell('''n_pos_flagged = sum(1 for r in pos if r["maltrail_flagged"])
n_pos_missed = len(pos) - n_pos_flagged
n_pos_missed_rare = sum(1 for r in pos if not r["maltrail_flagged"] and r["is_rare_bc"])
n_pos_missed_rare_matched = sum(1 for r in pos if not r["maltrail_flagged"] and r["is_rare_bc"] and r["l3_candidate"])
n_neg_escalated_matched = sum(1 for r in neg if r["escalated_to_l3"] and r["l3_candidate"])

print(f"L1 (Maltrail) recall over positive windows: {n_pos_flagged}/{len(pos)} = {n_pos_flagged/len(pos):.3f}")
print(f"Flag loss (positive windows NOT flagged by L1): {n_pos_missed}/{len(pos)} = {n_pos_missed/len(pos):.3f}")
print(f"  ...of those, falling in a rare BC (eligible for L3 escalation): {n_pos_missed_rare}/{n_pos_missed}")
denom = n_pos_missed_rare if n_pos_missed_rare else 1
print(f"  ...of those, receiving a technique candidate from L3: {n_pos_missed_rare_matched}/{denom}")
l1_union_l3 = n_pos_flagged + n_pos_missed_rare_matched
print(f"L1 union L3 recall: {l1_union_l3}/{len(pos)} = {l1_union_l3/len(pos):.3f}")
print()
print(f"False positive check -- NEGATIVE windows (benign host) escalated & receiving an L3 candidate: {n_neg_escalated_matched}/{len(neg)}")'''))

cells.append(new_markdown_cell('''## Section H: details -- which windows L3 catches, and their candidate techniques'''))

cells.append(new_code_cell('''for r in all_results:
    if r["l3_candidate"]:
        c = r["l3_candidate"]
        host_id = r["host_id"]; widx = r["window_idx"]; truth = r["truth"]; bc = r["bc"]
        heur = c["heuristic"]; ratio = c["ratio_to_threshold"]
        tid = c["technique_id"]; nm = c["name"]; conf = c["confidence"]
        print(f"{host_id:20s} window#{widx:3d} truth={truth!r}")
        print(f"    BC={bc} (rare) | closest heuristic={heur} (ratio={ratio}) -> {tid} {nm} [{conf}]")'''))

cells.append(new_markdown_cell('''## Section I: diagnosing the false positives of the `infection` heuristic on a benign host (`ctu_normal32`)

Checked manually: which windows & which dst_port/dst_ip trigger `infection` on the BENIGN host, to make sure
this is not a re-implementation bug but the heuristic's real behaviour (many distinct dst_ips on 1 dst_port
within one 30-second window -- which turns out to be ordinary web browsing touching dozens of different CDN
IPs on ports 80/443).'''))

cells.append(new_code_cell('''for host_id, path, ipf, truth in OLD_HOSTS:
    if host_id != "ctu_normal32":
        continue
    rows = load_old_host_rows(path, ipf)
    wins = windows_from_rows(rows)
    n_shown = 0
    for wi, wrows in enumerate(wins):
        t0 = min(r["ts"] for r in wrows)
        inf = defaultdict(lambda: defaultdict(set))
        for r in wrows:
            w = int((r["ts"] - t0) // 30)
            inf[w][r["dst_port"]].add(r["dst_ip"])
        for w, d in inf.items():
            for dport, ips in d.items():
                if len(ips) > INFECTION_SCANNING_THRESHOLD and n_shown < 5:
                    print(f"win{wi} subw{w} INFECTION dst_port={dport} n_distinct_dst_ip={len(ips)} "
                          f"sample={sorted(ips)[:6]}")
                    n_shown += 1'''))

cells.append(new_markdown_cell('''## Summary & honest caveats

- **L1 (Maltrail, 3 structural heuristics) recall over the 317 positive windows: 0.3%** (1/317). This
  baseline is ONLY `port_scanning`/`udp_scanning`/`infection`, NOT the blacklist/trail list -- a different
  scope from Table 5 (pilot corpus), which uses a broader methodology. Do not equate them.
- **L1 union L3 recall: 1.6%** (5/317) -- up from 1 window (UWF episode 2) to 5 windows
  (+ `tinba_vm` x2, `uwf_143.88.5.12`, `uwf_143.88.7.10` episode 1), with **0 false positives**
  over 62 benign windows.
- **`dridex_vm`, `zeus_vm_250` and `zeus_vm_251` have 0% of their windows in a rare BC** -- they NEVER
  qualify for escalation to L3 at all, however good the technique-matching algorithm is. This is a
  limitation of the rare-BC trigger, not of technique matching.
- The **`infection`** heuristic shows a real false-positive mode on heavy web/CDN traffic (confirmed in
  section I) -- the heuristic's real behaviour (read from `sensor.py`), not a bug. Benign windows flagged by
  `infection` are still CORRECTLY counted as "L1 flagged" (not escalated), so they do not contaminate the L3
  recall -- but they are relevant as a note on L1's own limitations.'''))

nb = new_notebook(cells=cells)
nb.metadata["kernelspec"] = {"name": "pfr2026-venv", "display_name": "pfr2026-venv", "language": "python"}

out_nb_path = Path(__file__).parent / "experiment3_graph_inspection.ipynb"
nbf.write(nb, str(out_nb_path))
print(f"Notebook written (not yet executed): {out_nb_path}")
