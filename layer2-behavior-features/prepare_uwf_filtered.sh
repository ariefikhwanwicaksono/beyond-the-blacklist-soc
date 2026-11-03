#!/bin/bash
# Build the uwf_filtered/ inputs that compute_behavior_classes.py reads (UWF_FILTERED_DIR).
#
# The two UWF-ZeekData22 hosts used in the paper (143.88.5.12 and 143.88.7.10) are taken from the
# UWF-ZeekData22 CSV shards listed in UWF_SHARDS.sha256. This step keeps every shard row that contains
# the host's address as a comma-delimited field; compute_behavior_classes.py then keeps only rows whose
# src_ip equals the host, so any superset of those rows gives the same result.
#
# Verified 2026-11-03: running this script and then compute_behavior_classes.py reproduces the committed
# bc_results.json byte for byte.
#
# Usage: prepare_uwf_filtered.sh <dir_with_uwf_csv_shards> [output_dir]
#        (default output_dir: uwf_filtered/ next to this script)
set -eu
SRC="$1"
OUT="${2:-$(cd "$(dirname "$0")" && pwd)/uwf_filtered}"
mkdir -p "$OUT"

grep -h -F ",143.88.5.12," "$SRC"/*.csv > "$OUT/uwf_5_12.csv"
grep -h -F ",143.88.7.10," "$SRC"/*.csv > "$OUT/uwf_7_10.csv"

echo "uwf_5_12.csv: $(wc -l < "$OUT/uwf_5_12.csv") rows (expected 502528)"
echo "uwf_7_10.csv: $(wc -l < "$OUT/uwf_7_10.csv") rows (expected 4134)"
echo "Next: UWF_FILTERED_DIR=\"$OUT\" python3 compute_behavior_classes.py"
