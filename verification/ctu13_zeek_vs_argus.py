"""CTU-13 scenario 42: how much of the normal hosts' traffic Zeek can read from the 54-byte-truncated pcap.

Reference = Stratosphere Argus flows computed from the full pcap. Paper claim (NO-GO for CTU-13):
  * UDP: Zeek packets/IP-bytes/duration match Argus for ~99.8% of flows.
  * TCP: Zeek reads only ~4.6% of packets and ~4.3% of IP bytes; ~86% of TCP flows have zero packets parsed,
    because TCP options (Linux timestamps) push the TCP header past the 54-byte snap length.

Usage: python3 ctu13_zeek_vs_argus.py <out_dir of ctu13_extract_normal_hosts.sh>
"""
import sys
from datetime import datetime, timezone, timedelta

import numpy as np
import pandas as pd

S = sys.argv[1]
CEST = timezone(timedelta(hours=2))  # binetflow StartTime is local Prague time (CEST) on 2011-08-10

fields = open(f"{S}/conn_normal.log").readline().rstrip("\n").split("\t")[1:]
z = pd.read_csv(f"{S}/conn_normal.log", sep="\t", skiprows=1, names=fields, na_values="-", low_memory=False)
for c in ["ts", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes"]:
    z[c] = pd.to_numeric(z[c], errors="coerce")
b = pd.read_csv(f"{S}/bf_normal.csv")
b["ts"] = [datetime.strptime(t, "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=CEST).timestamp() for t in b["StartTime"]]

# ---------------- UDP: nearest Zeek row with the same 5-tuple, |dt| <= 2 s ----------------
zu = z[z.proto == "udp"].rename(columns={"id.orig_h": "src", "id.orig_p": "sport", "id.resp_h": "dst", "id.resp_p": "dport"})
bu = b[b.Proto == "udp"].rename(columns={"SrcAddr": "src", "Sport": "sport", "DstAddr": "dst", "Dport": "dport"})
for d in (zu, bu):
    d["sport"] = pd.to_numeric(d["sport"], errors="coerce").astype("Int64")
    d["dport"] = pd.to_numeric(d["dport"], errors="coerce").astype("Int64")
m = pd.merge_asof(bu.sort_values("ts"), zu.sort_values("ts")[["ts", "src", "sport", "dst", "dport", "uid", "duration",
                  "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes"]],
                  on="ts", by=["src", "sport", "dst", "dport"], tolerance=2.0, direction="nearest")
m = m[m.uid.notna()]
zp = m.orig_pkts + m.resp_pkts
zb = m.orig_ip_bytes + m.resp_ip_bytes
print(f"UDP flows matched: {len(m)}/{len(bu)}")
print(f"  packets equal to Argus: {100 * (zp == m.TotPkts).mean():.1f}%")
print(f"  IP bytes / (Argus TotBytes - 14*pkts): median {(zb / (m.TotBytes - 14 * m.TotPkts)).median():.3f}")
print(f"  |duration diff| < 0.01 s: {100 * ((m.duration - m.Dur).abs() < 0.01).mean():.1f}%")

# ---------------- TCP: ALL Zeek rows with the same undirected 5-tuple inside the Argus flow's span ----------------
zt = z[z.proto == "tcp"].copy()
for c in ["duration", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes"]:
    zt[c] = zt[c].fillna(0)
zt["pkts"] = zt.orig_pkts + zt.resp_pkts
zt["ipb"] = zt.orig_ip_bytes + zt.resp_ip_bytes
zt["k"] = [tuple(sorted([(a, int(p)), (c, int(q))])) for a, p, c, q in
           zip(zt["id.orig_h"], zt["id.orig_p"], zt["id.resp_h"], zt["id.resp_p"])]
groups = {k: g for k, g in zt.groupby("k")}
bt = b[b.Proto == "tcp"].copy()
rows = []
for r in bt.itertuples():
    g = groups.get(tuple(sorted([(r.SrcAddr, int(r.Sport)), (r.DstAddr, int(r.Dport))])))
    if g is not None:
        g = g[(g.ts >= r.ts - 2) & (g.ts <= r.ts + r.Dur + 2)]
    rows.append((0, 0, 0) if g is None or g.empty else (len(g), g.pkts.sum(), g.ipb.sum()))
bt[["z_rows", "z_pkts", "z_ipb"]] = rows
arg_ipb = bt.TotBytes - 14 * bt.TotPkts
print(f"TCP flows (Argus): {len(bt)}")
print(f"  with >=1 Zeek row in span: {100 * (bt.z_rows > 0).mean():.1f}%")
print(f"  with >=1 packet parsed by Zeek: {100 * (bt.z_pkts > 0).mean():.1f}%  (zero packets: {100 * (bt.z_pkts == 0).mean():.1f}%)")
print(f"  packets read: {bt.z_pkts.sum():,.0f}/{bt.TotPkts.sum():,.0f} = {bt.z_pkts.sum() / bt.TotPkts.sum():.3f}")
print(f"  IP bytes read: {bt.z_ipb.sum():,.0f}/{arg_ipb.sum():,.0f} = {bt.z_ipb.sum() / arg_ipb.sum():.3f}")
print(f"  Zeek rows per Argus flow: mean {bt.z_rows.mean():.2f}")
