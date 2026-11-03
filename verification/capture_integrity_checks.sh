#!/bin/bash
# Truncation/integrity checks used to accept CTU-Normal-32/33 (and reject CTU-13) as benign-host sources.
#   1. weird.log: truncated_header / truncated_tcp_payload counts
#   2. capture_loss.log: percent lost per interval
#   3. conn.log: TCP rows with zero packets parsed
#   4. Zeek vs Stratosphere Argus binetflow: packets and IP bytes per protocol
#      (Argus TotBytes includes the 14-byte Ethernet header per packet, so IP bytes = TotBytes - 14*TotPkts)
# Paper values (Zeek 8.2.2): CTU-Normal-32 TCP packets 1,493,813 = 1,493,813; CTU-Normal-33 TCP packets
# 375,264 = 375,264 and TCP IP bytes 230,777,098 = 230,777,098; 0 truncated_*; capture loss 0.0%.
#
# Usage: capture_integrity_checks.sh <zeek_output_dir> <stratosphere.binetflow>
set -eu
Z="$1"; BF="$2"
echo "== weird.log (truncation-related)"
grep -v '^#' "$Z/weird.log" | cut -f7 | grep -E '^truncated' | sort | uniq -c || echo "   none"
echo "== capture_loss.log (percent_lost per interval)"
grep -v '^#' "$Z/capture_loss.log" | awk -F'\t' '{print "   " $NF}' | sort | uniq -c
echo "== conn.log TCP rows with zero packets"
awk -F'\t' '!/^#/ && $7=="tcp"{n++; if($17+$19==0) z++} END{printf "   %d of %d (%.1f%%)\n", z, n, (n?100*z/n:0)}' "$Z/conn.log"
echo "== packets / IP bytes per protocol: Zeek vs Argus"
awk -F'\t' '!/^#/ && ($7=="tcp"||$7=="udp"){p[$7]+=$17+$19; b[$7]+=$18+$20} END{for(k in p) printf "   Zeek  %s pkts=%d ipbytes=%d\n", k, p[k], b[k]}' "$Z/conn.log" | sort
DELIM=$(head -1 "$BF" | grep -q $'\t' && echo $'\t' || echo ',')
awk -F"$DELIM" 'NR>1 && ($3=="tcp"||$3=="udp"){p[$3]+=$12; b[$3]+=$13-14*$12} END{for(k in p) printf "   Argus %s pkts=%d ipbytes=%d\n", k, p[k], b[k]}' "$BF" | sort
