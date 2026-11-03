"""
Layer 2 sensitivity sweep: does the paper's eps / rare-BC-threshold choice
(eps_port=0.2, eps_dstip=0.3, rare_threshold=0.03) matter for its two
qualitative findings (Section 2.2 / sec:layer2), or do they hold across a
neighbourhood of alternative values?

  Claim 1: a benign host (CTU-Normal-32 or -33) shares its dominant
           behaviour class with a malware host (RAT pair / Dridex).
  Claim 2: Tinba and uwf_143.88.7.10 fall into rare behaviour classes at a
           higher rate than the pooled corpus average.

RU values (ru_sp, ru_dp, ru_di) are independent of eps -- only the
Low/Medium/High discretisation depends on it -- so they are computed once
per window and re-discretised cheaply for every grid point, rather than
re-reading the raw Zeek/CSV data 27 times.

Reuses compute_behavior_classes.py's own load/window functions unmodified,
so this sweep is built on exactly the same windowing and data-loading code
the paper's reported results come from -- not a reimplementation that could
silently diverge from it.
"""
import sys, os, json
from collections import Counter
from itertools import product

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compute_behavior_classes import (
    OLD_HOSTS, UWF_FILTERED_FILES, load_old_host_rows, load_uwf_host_rows,
    windows_from_rows, norm_entropy,
)


def label_RU(ru, eps):
    if ru <= eps:
        return 0
    elif ru < 1 - eps:
        return 1
    else:
        return 2


def bc_id(l_sp, l_dp, l_di):
    return l_sp * 9 + l_dp * 3 + l_di


def compute_ru_for_windows(windows):
    out = []
    for wrows in windows:
        ru_sp = norm_entropy(Counter(r["src_port"] for r in wrows))
        ru_dp = norm_entropy(Counter(r["dst_port"] for r in wrows))
        ru_di = norm_entropy(Counter(r["dst_ip"] for r in wrows))
        out.append((ru_sp, ru_dp, ru_di))
    return out


def main():
    host_ru = {}
    for host_id, path, ipf, truth in OLD_HOSTS:
        rows = load_old_host_rows(path, ipf)
        wins = windows_from_rows(rows)
        host_ru[host_id] = compute_ru_for_windows(wins)
        print(f"{host_id}: {len(wins)} windows loaded", file=sys.stderr)

    for host_id, (path, ip, truth) in UWF_FILTERED_FILES.items():
        rows = load_uwf_host_rows(path, ip)
        wins = windows_from_rows(rows)
        host_ru[host_id] = compute_ru_for_windows(wins)
        print(f"{host_id}: {len(wins)} windows loaded", file=sys.stderr)

    EPS_PORT_GRID = [0.15, 0.20, 0.25]
    EPS_DSTIP_GRID = [0.25, 0.30, 0.35]
    RARE_THRESH_GRID = [0.02, 0.03, 0.05]

    results = []
    for eps_port, eps_di, rare_t in product(EPS_PORT_GRID, EPS_DSTIP_GRID, RARE_THRESH_GRID):
        pooled = Counter()
        host_bcs = {}
        for host_id, ru_list in host_ru.items():
            bcs = []
            for ru_sp, ru_dp, ru_di in ru_list:
                l_sp = label_RU(ru_sp, eps_port)
                l_dp = label_RU(ru_dp, eps_port)
                l_di = label_RU(ru_di, eps_di)
                bc = bc_id(l_sp, l_dp, l_di)
                bcs.append(bc)
                pooled[bc] += 1
            host_bcs[host_id] = bcs

        total = sum(pooled.values())
        rare_bcs = set(bc for bc, c in pooled.items() if (c / total) < rare_t) if total else set()

        dom_bc = {h: Counter(bcs).most_common(1)[0][0] for h, bcs in host_bcs.items() if bcs}

        rat_bcs = {dom_bc.get("zeus_vm_250"), dom_bc.get("zeus_vm_251")} - {None}
        claim1 = dom_bc.get("ctu_normal32") in rat_bcs if rat_bcs else False
        claim2 = (dom_bc.get("ctu_normal33") is not None
                  and dom_bc.get("ctu_normal33") == dom_bc.get("dridex_vm"))

        overall_rare_frac = (sum(1 for bcs in host_bcs.values() for b in bcs if b in rare_bcs) / total) if total else 0
        rare_frac = {}
        for h in ("tinba_vm", "uwf_143.88.7.10"):
            bcs = host_bcs.get(h, [])
            rare_frac[h] = (sum(1 for b in bcs if b in rare_bcs) / len(bcs)) if bcs else None
        claim2_tinba = rare_frac["tinba_vm"] is not None and rare_frac["tinba_vm"] > overall_rare_frac
        claim2_uwf710 = rare_frac["uwf_143.88.7.10"] is not None and rare_frac["uwf_143.88.7.10"] > overall_rare_frac

        results.append(dict(
            eps_port=eps_port, eps_dstip=eps_di, rare_threshold=rare_t,
            n_rare_bcs=len(rare_bcs),
            claim1_ctu32_shares_with_rat=claim1,
            claim2_ctu33_shares_with_dridex=claim2,
            claim3_tinba_disproportionately_rare=claim2_tinba,
            claim4_uwf710_disproportionately_rare=claim2_uwf710,
            overall_rare_frac=round(overall_rare_frac, 4),
            rare_frac_tinba=round(rare_frac["tinba_vm"], 4) if rare_frac["tinba_vm"] is not None else None,
            rare_frac_uwf710=round(rare_frac["uwf_143.88.7.10"], 4) if rare_frac["uwf_143.88.7.10"] is not None else None,
        ))

    n_total = len(results)
    n_c1 = sum(r["claim1_ctu32_shares_with_rat"] for r in results)
    n_c2 = sum(r["claim2_ctu33_shares_with_dridex"] for r in results)
    n_c3 = sum(r["claim3_tinba_disproportionately_rare"] for r in results)
    n_c4 = sum(r["claim4_uwf710_disproportionately_rare"] for r in results)

    summary = dict(
        grid_size=n_total,
        eps_port_grid=EPS_PORT_GRID,
        eps_dstip_grid=EPS_DSTIP_GRID,
        rare_threshold_grid=RARE_THRESH_GRID,
        baseline_params=dict(eps_port=0.2, eps_dstip=0.3, rare_threshold=0.03),
        claim1_holds_in=f"{n_c1}/{n_total}",
        claim2_holds_in=f"{n_c2}/{n_total}",
        claim3_holds_in=f"{n_c3}/{n_total}",
        claim4_holds_in=f"{n_c4}/{n_total}",
        detail=results,
    )

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "eps_sensitivity_sweep.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps({k: v for k, v in summary.items() if k != "detail"}, indent=2))
    print(f"\nFull detail (27 grid points) saved to {out_path}")


if __name__ == "__main__":
    main()
