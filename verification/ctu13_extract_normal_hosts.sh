#!/bin/bash
# Extract the three documented normal hosts of CTU-13 scenario 42 (CTU-Malware-Capture-Botnet-42) from
#   (a) Zeek conn.log produced from the public *truncated* pcap (capture20110810.truncated.pcap.bz2), and
#   (b) the Stratosphere bidirectional Argus flows (detailed-bidirectional-flow-labels/capture20110810.binetflow),
#       which Stratosphere computed from the full (non-public) pcap and therefore serve as the reference.
# Zeek was run exactly as for the other captures:  bzcat capture20110810.truncated.pcap.bz2 | zeek -C -r - local
#
# Usage: ctu13_extract_normal_hosts.sh <zeek_conn.log> <capture20110810.binetflow> <out_dir>
set -eu
CONN="$1"; BF="$2"; OUT="$3"
mkdir -p "$OUT"
NORMAL='147.32.84.170|147.32.84.164|147.32.84.134'
grep '^#fields' "$CONN" > "$OUT/conn_normal.log"
awk -F'\t' -v re="^($NORMAL)$" '!/^#/ && ($3 ~ re || $5 ~ re)' "$CONN" >> "$OUT/conn_normal.log"
head -1 "$BF" > "$OUT/bf_normal.csv"
grep -E 'From-Normal-V42-(Stribrek|Grill|Jist)' "$BF" >> "$OUT/bf_normal.csv"
echo "Zeek rows involving the 3 hosts: $(( $(wc -l < "$OUT/conn_normal.log") - 1 ))"
echo "Argus From-Normal flows (3 hosts): $(( $(wc -l < "$OUT/bf_normal.csv") - 1 ))"
