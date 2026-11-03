"""
Experiment 3 prototype: Layer 2 -> Layer 3 escalation + ATT&CK technique matching.

Trigger for escalation to L3 (NOT a newly invented threshold; it uses what already exists in the architecture):
  the window is NOT flagged by Maltrail (L1) AND the window falls in a rare BC class (L2, unsupervised).

For an escalated window: compute the raw metrics EXACTLY as measured by each Maltrail heuristic
(distinct dst-ports per dst_ip within a 30-second window for port_scanning; distinct dst_ips per
dst_port within a 30-second window for infection; the same but UDP-only for udp_scanning), pick the
heuristic with the HIGHEST ratio-to-threshold (even if below Maltrail's official threshold), and map it
to a candidate ATT&CK technique via a table (grounded by reading sensor.py directly plus the technique
definitions, NOT from host labels).

Ground-truth labels (truth per host) are only opened in the very last evaluation step.
"""
import os, sys, re, json
from pathlib import Path
from collections import defaultdict, Counter

# Repository root; override with env PFR_BASE. (The original version used an absolute path of the
# analysis environment, ~/mnt/PFR 2026.)
BASE = Path(os.environ.get("PFR_BASE", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(BASE / "layer2-behavior-features"))
from compute_behavior_classes import (
    OLD_HOSTS, UWF_FILTERED_FILES, load_old_host_rows, load_uwf_host_rows,
    windows_from_rows, compute_bc_for_windows,
)

RARE_BCS = {15, 19, 21, 24}  # from bc_results.json rare_bcs

settings_text = (BASE / "layer1-maltrail-zeek" / "tools" / "maltrail" / "core" / "settings.py").read_text()
def read_const(name):
    m = re.search(rf"^{name}\s*=\s*(\d+)", settings_text, re.M)
    return int(m.group(1))
PORT_SCANNING_THRESHOLD = read_const("PORT_SCANNING_THRESHOLD")
INFECTION_SCANNING_THRESHOLD = read_const("INFECTION_SCANNING_THRESHOLD")
SCAN_WINDOW_SEC = 30

# Mapping table heuristic -> candidate ATT&CK technique.
# Grounding: read directly from the mechanism in sensor.py (not just the heuristic's name), plus the
# official technique definitions on attack.mitre.org. Honest confidence label per row -- this is a NEW
# table that had not been verified before, unlike the existing per-host grounding.
HEURISTIC_TECHNIQUE_MAP = {
    # port_scanning: 1 dst_ip, many distinct dst_ports from 1 src within 1 window -- exactly the definition
    # of T1046 (already used earlier in this project to ground episode 2 of .7.10). [HIGH]
    "port_scanning": dict(technique_id="T1046", name="Network Service Discovery", confidence="HIGH"),
    # udp_scanning: same logic as port_scanning but for UDP -- same technique, slightly lower confidence
    # because it had not been grounded before in this project. [MEDIUM]
    "udp_scanning": dict(technique_id="T1046", name="Network Service Discovery", confidence="MEDIUM"),
    # infection: 1 dst_port, many distinct dst_ips from 1 local src within 1 window -- sweeps many
    # HOSTS on the same port/service, a different axis from port_scanning. Closest to T1595.001
    # (Active Scanning: Scanning IP Blocks). [MEDIUM]
    "infection": dict(technique_id="T1595.001", name="Active Scanning: Scanning IP Blocks", confidence="MEDIUM"),
}


def sub_window_metrics(rows, win_sec=SCAN_WINDOW_SEC):
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


def main():
    all_results = []

    def process(host_id, rows, truth):
        wins = windows_from_rows(rows)  # 300-second windows, exactly as in compute_behavior_classes.py
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
                    candidate = dict(heuristic=best_heur, ratio_to_threshold=round(ratios[best_heur], 3),
                                      **mapping)

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

    out_dir = BASE / "experiment3-graph-inspection" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "experiment3_window_results.json"
    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"Saved: {out_path} ({len(all_results)} windows)")

    # ---- quick summary (ground truth is only opened here) ----
    BENIGN_HOSTS = {"ctu_normal32", "ctu_normal33"}
    pos = [r for r in all_results if r["host_id"] not in BENIGN_HOSTS]
    neg = [r for r in all_results if r["host_id"] in BENIGN_HOSTS]

    print(f"\nTotal windows: {len(all_results)}  (positive/malicious-host: {len(pos)}, negative/benign-host: {len(neg)})")
    print("\n--- per host: n_windows, n_rare_bc, n_maltrail_flagged, n_escalated_to_l3, n_l3_matched ---")
    by_host = defaultdict(list)
    for r in all_results:
        by_host[r["host_id"]].append(r)
    for h, rs in by_host.items():
        n_rare = sum(1 for r in rs if r["is_rare_bc"])
        n_flag = sum(1 for r in rs if r["maltrail_flagged"])
        n_esc = sum(1 for r in rs if r["escalated_to_l3"])
        n_match = sum(1 for r in rs if r["l3_candidate"])
        print(f"  {h:20s} n={len(rs):3d} rare_bc={n_rare:3d} maltrail_flag={n_flag:3d} escalated={n_esc:3d} l3_matched={n_match:3d}")

    n_pos_flagged = sum(1 for r in pos if r["maltrail_flagged"])
    n_pos_missed = len(pos) - n_pos_flagged
    n_pos_missed_rare = sum(1 for r in pos if not r["maltrail_flagged"] and r["is_rare_bc"])
    n_pos_missed_rare_matched = sum(1 for r in pos if not r["maltrail_flagged"] and r["is_rare_bc"] and r["l3_candidate"])
    n_neg_escalated_matched = sum(1 for r in neg if r["escalated_to_l3"] and r["l3_candidate"])

    print(f"\nL1 (Maltrail) recall over positive windows: {n_pos_flagged}/{len(pos)} = {n_pos_flagged/len(pos):.3f}")
    print(f"Flag loss (positive windows NOT flagged by L1): {n_pos_missed}/{len(pos)} = {n_pos_missed/len(pos):.3f}")
    print(f"  ...of those, falling in a rare BC (eligible for L3 escalation): {n_pos_missed_rare}/{n_pos_missed}")
    print(f"  ...of those, receiving a technique candidate from L3: {n_pos_missed_rare_matched}/{n_pos_missed_rare if n_pos_missed_rare else 1}")
    print(f"L1 union L3 recall: {(n_pos_flagged + n_pos_missed_rare_matched)}/{len(pos)} = {(n_pos_flagged + n_pos_missed_rare_matched)/len(pos):.3f}")
    print(f"\nFalse positive check -- NEGATIVE windows (benign host) escalated & receiving an L3 candidate: {n_neg_escalated_matched}/{len(neg)}")

    summary_lines = []
    summary_lines.append("# Experiment 3 (prototype): Layer2->Layer3 escalation + ATT&CK technique matching\n")
    summary_lines.append("Generated automatically by experiment3_prototype.py -- see that script for the full methodology.\n")
    summary_lines.append(f"\nTotal windows: {len(all_results)} (positive={len(pos)}, negative/benign={len(neg)})\n")
    summary_lines.append("\n| Host | n windows | rare BC | L1 flagged | escalated to L3 | L3 candidate |\n|---|---|---|---|---|---|\n")
    for h, rs in by_host.items():
        n_rare = sum(1 for r in rs if r["is_rare_bc"])
        n_flag = sum(1 for r in rs if r["maltrail_flagged"])
        n_esc = sum(1 for r in rs if r["escalated_to_l3"])
        n_match = sum(1 for r in rs if r["l3_candidate"])
        summary_lines.append(f"| {h} | {len(rs)} | {n_rare} | {n_flag} | {n_esc} | {n_match} |\n")
    summary_lines.append(f"\nL1 recall (positive windows): {n_pos_flagged}/{len(pos)} = {n_pos_flagged/len(pos):.3f}\n")
    summary_lines.append(f"L1 union L3 recall: {(n_pos_flagged + n_pos_missed_rare_matched)}/{len(pos)} = {(n_pos_flagged + n_pos_missed_rare_matched)/len(pos):.3f}\n")
    summary_lines.append(f"False positives (benign windows escalated+matched): {n_neg_escalated_matched}/{len(neg)}\n")
    summary_lines.append("\n## Important caveats\n")
    summary_lines.append("- The L1 baseline here is ONLY the 3 structural heuristics (port_scanning, udp_scanning, infection),"
                          " NOT the blacklist/trail list -- a different scope from Table 5 (pilot corpus), which uses a"
                          " broader methodology.\n")
    summary_lines.append("- dridex_vm, zeus_vm_250 and zeus_vm_251 have 0% of their windows in a rare BC -- they NEVER"
                          " qualify for escalation to L3, regardless of the technique-matching algorithm.\n")
    summary_lines.append("- The 'infection' heuristic (number of distinct dst_ips to 1 dst_port from 1 src within 30 seconds)"
                          " fires 10x on ctu_normal32 (benign) purely because ordinary web browsing touches dozens of"
                          " different CDN IPs on ports 80/443 -- manually confirmed to be the heuristic's real behaviour"
                          " (read from sensor.py), not a re-implementation bug.\n")
    (out_dir / "summary.md").write_text("".join(summary_lines))
    print(f"Summary: {out_dir / 'summary.md'}")


if __name__ == "__main__":
    main()
