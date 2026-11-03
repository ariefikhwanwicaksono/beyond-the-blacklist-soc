import csv, math, json, sys, os
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
# Input/output paths can be overridden via env. (The original version used absolute paths of the analysis
# environment: ~/mnt/PFR 2026/.../zeek_out, ~/uwf_filtered and ~/bc_results.json -- same data.)
BASE_ZEEK = os.environ.get("PFR_ZEEK_OUT", os.path.join(HERE, "..", "layer1-maltrail-zeek", "data", "zeek_out"))
FILTERED_DIR = os.environ.get("UWF_FILTERED_DIR", os.path.join(HERE, "uwf_filtered"))  # see prepare_uwf_filtered.sh
BC_RESULTS_OUT = os.environ.get("BC_RESULTS_OUT", os.path.join(HERE, "bc_results.json"))

OLD_HOSTS = [
    ("tinba_vm",     f"{BASE_ZEEK}/tinba/conn.log",      None,            "malware (DGA)"),
    ("dridex_vm",    f"{BASE_ZEEK}/dridex/conn.log",     None,            "malware (C2)"),
    ("zeus_vm_250",  f"{BASE_ZEEK}/zeus_dedup/conn.log", "192.168.0.250", "malware (RAT)"),
    ("zeus_vm_251",  f"{BASE_ZEEK}/zeus_dedup/conn.log", "192.168.0.251", "malware (RAT)"),
    ("ctu_normal32", f"{BASE_ZEEK}/ctu_normal32/conn.log", None,          "benign"),
    ("ctu_normal33", f"{BASE_ZEEK}/ctu_normal33/conn.log", None,          "benign"),
]

# column order in the UWF-ZeekData22 CSV export, confirmed via header inspection:
UWF_COLS = ["resp_pkts","service","orig_ip_bytes","local_resp","missed_bytes","protocol",
            "duration","conn_state","dest_ip","orig_pkts","community_id","resp_ip_bytes",
            "dest_port","orig_bytes","local_orig","datetime","history","resp_bytes","uid",
            "src_port","ts","src_ip","mitre_attack_tactics"]
IDX = {c: i for i, c in enumerate(UWF_COLS)}

UWF_FILTERED_FILES = {
    "uwf_143.88.5.12": (f"{FILTERED_DIR}/uwf_5_12.csv", "143.88.5.12",
                         "attacker (DNS enumeration, Reconnaissance)"),
    "uwf_143.88.7.10": (f"{FILTERED_DIR}/uwf_7_10.csv", "143.88.7.10",
                         "attacker (2 episodes: Reconnaissance + Discovery)"),
}


def norm_entropy(counter):
    n = len(counter)
    if n <= 1:
        return 0.0
    total = sum(counter.values())
    h = -sum((c / total) * math.log2(c / total) for c in counter.values())
    return h / math.log2(n)


def label_RU(ru, eps):
    if ru <= eps:
        return 0
    elif ru < 1 - eps:
        return 1
    else:
        return 2


def bc_id(l_srcport, l_dstport, l_dstip):
    return l_srcport * 9 + l_dstport * 3 + l_dstip


def load_zeek_conn(path):
    fields = None
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                parts = line.rstrip("\n").split("\t")
                if fields and len(parts) == len(fields):
                    yield dict(zip(fields, parts))


def load_old_host_rows(path, ip_filter):
    rows = []
    for r in load_zeek_conn(path):
        if ip_filter and r.get("id.orig_h") != ip_filter:
            continue
        try:
            ts = float(r["ts"])
        except (ValueError, KeyError):
            continue
        rows.append({
            "ts": ts,
            "src_port": r.get("id.orig_p", "-"),
            "dst_port": r.get("id.resp_p", "-"),
            "dst_ip": r.get("id.resp_h", "-"),
            "proto": r.get("proto", "-"),
            "conn_state": r.get("conn_state", "-"),
        })
    return rows


def load_uwf_host_rows(path, ip):
    rows = []
    with open(path, newline="", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) != len(UWF_COLS):
                continue
            if parts[IDX["src_ip"]] != ip:
                continue
            try:
                ts = float(parts[IDX["ts"]])
            except ValueError:
                continue
            rows.append({
                "ts": ts,
                "src_port": parts[IDX["src_port"]],
                "dst_port": parts[IDX["dest_port"]],
                "dst_ip": parts[IDX["dest_ip"]],
                "proto": parts[IDX["protocol"]],
                "conn_state": parts[IDX["conn_state"]],
                "datetime": parts[IDX["datetime"]],
                "tactic": parts[IDX["mitre_attack_tactics"]],
            })
    return rows


def windows_from_rows(rows, win_sec=300, min_flows=10):
    if not rows:
        return []
    t0 = min(r["ts"] for r in rows)
    buckets = defaultdict(list)
    for r in rows:
        w = int((r["ts"] - t0) // win_sec)
        buckets[w].append(r)
    out = []
    for w in sorted(buckets):
        wrows = buckets[w]
        if len(wrows) < min_flows:
            continue
        out.append(wrows)
    return out


def compute_bc_for_windows(windows):
    results = []
    for wrows in windows:
        ru_sp = norm_entropy(Counter(r["src_port"] for r in wrows))
        ru_dp = norm_entropy(Counter(r["dst_port"] for r in wrows))
        ru_di = norm_entropy(Counter(r["dst_ip"] for r in wrows))
        l_sp = label_RU(ru_sp, 0.2)
        l_dp = label_RU(ru_dp, 0.2)
        l_di = label_RU(ru_di, 0.3)
        bc = bc_id(l_sp, l_dp, l_di)
        tcp_rows = [r for r in wrows if r["proto"] == "tcp"]
        fail_ratio = None
        if tcp_rows:
            failed = sum(1 for r in tcp_rows if r["conn_state"] in ("S0", "REJ", "OTH", "RSTOS0"))
            fail_ratio = failed / len(tcp_rows)
        results.append(dict(ru_sp=round(ru_sp, 4), ru_dp=round(ru_dp, 4), ru_di=round(ru_di, 4),
                             l_sp=l_sp, l_dp=l_dp, l_di=l_di, bc=bc,
                             n_flows=len(wrows), fail_ratio=fail_ratio))
    return results


def main():
    all_host_windows = {}

    for host_id, path, ipf, truth in OLD_HOSTS:
        rows = load_old_host_rows(path, ipf)
        wins = windows_from_rows(rows)
        res = compute_bc_for_windows(wins)
        all_host_windows[host_id] = dict(truth=truth, windows=res, n_raw_rows=len(rows))
        print(f"{host_id}: {len(rows)} raw rows -> {len(res)} valid windows", file=sys.stderr)

    for host_id, (path, ip, truth) in UWF_FILTERED_FILES.items():
        rows = load_uwf_host_rows(path, ip)
        wins = windows_from_rows(rows)
        res = compute_bc_for_windows(wins)
        all_host_windows[host_id] = dict(truth=truth, windows=res, n_raw_rows=len(rows))
        print(f"{host_id}: {len(rows)} raw rows -> {len(res)} valid windows", file=sys.stderr)

    pooled = Counter()
    total_windows = 0
    for h, d in all_host_windows.items():
        for w in d["windows"]:
            pooled[w["bc"]] += 1
            total_windows += 1

    rare_bcs = sorted(bc for bc, c in pooled.items() if (c / total_windows) < 0.03) if total_windows else []

    summary = {}
    for host_id, d in all_host_windows.items():
        bcs = [w["bc"] for w in d["windows"]]
        if not bcs:
            summary[host_id] = dict(truth=d["truth"], n_raw_rows=d["n_raw_rows"], n_windows=0,
                                     note="NO VALID WINDOWS")
            continue
        cnt = Counter(bcs)
        dom_bc, dom_n = cnt.most_common(1)[0]
        frac_rare = sum(1 for b in bcs if b in rare_bcs) / len(bcs)
        fail_ratios = [w["fail_ratio"] for w in d["windows"] if w["fail_ratio"] is not None]
        summary[host_id] = dict(
            truth=d["truth"],
            n_raw_rows=d["n_raw_rows"],
            n_windows=len(bcs),
            dominant_bc=dom_bc,
            dominant_bc_frac=round(dom_n / len(bcs), 4),
            frac_in_rare_bc=round(frac_rare, 4),
            n_distinct_bc=len(cnt),
            bc_distribution={str(k): v for k, v in sorted(cnt.items())},
            fail_ratio_median=(sorted(fail_ratios)[len(fail_ratios)//2] if fail_ratios else None),
            fail_ratio_n=len(fail_ratios),
        )

    output = dict(
        methodology="Xu(2022) Ch.3: RU(srcPort)/RU(dstPort) eps=0.2, RU(dstIP) eps=0.3, "
                     "BC = 9*L(srcPort)+3*L(dstPort)+L(dstIP), windows=5min relative to each "
                     "host's own first timestamp, valid window >=10 flows, rare BC = pooled "
                     "frequency < 3% of total windows (data-driven, not hardcoded).",
        total_windows=total_windows,
        pooled_bc_distribution={str(k): v for k, v in sorted(pooled.items())},
        pooled_bc_distribution_pct={str(k): round(100 * v / total_windows, 2) for k, v in sorted(pooled.items())} if total_windows else {},
        rare_bc_threshold=0.03,
        rare_bcs=rare_bcs,
        per_host=summary,
    )

    with open(BC_RESULTS_OUT, "w") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
