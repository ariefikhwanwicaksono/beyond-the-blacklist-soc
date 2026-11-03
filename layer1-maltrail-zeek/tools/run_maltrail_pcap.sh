#!/bin/bash
# Run Maltrail (old/sensor.py, offline mode) on one pcap and split the NEW alert lines into
# data/maltrail_out/<key>.log. Maltrail writes to dated files (<YYYY-MM-DD>.log) according to the packet
# timestamp; pcaps with near-epoch timestamps land in 1990-01-01.log, which already holds alerts from other
# pcaps (tinba), so new lines are taken by byte offset recorded before the run, not by file name.
#
# Usage: run_maltrail_pcap.sh <key> <path_to_pcap>
set -u
KEY="$1"; PCAP="$2"
BASE="$(cd "$(dirname "$0")/.." && pwd)"   # the layer1-maltrail-zeek folder
OUT="$BASE/data/maltrail_out"
RUNLOG="$OUT/_run_${KEY}_console.txt"
cd "$BASE/tools/maltrail" || exit 1

if [ -e "$OUT/$KEY.log" ]; then echo "[!] $OUT/$KEY.log already exists -- remove/move it first so results are not mixed"; exit 1; fi

ls -la "$OUT" > "/tmp/before_${KEY}.txt"
# Size of each dated log before the run (macOS bash 3.2 has no associative arrays -> temp file).
SIZES="/tmp/sizes_before_${KEY}.tsv"
: > "$SIZES"
for f in "$OUT"/[0-9]*.log; do printf "%s\t%s\n" "$(stat -f%z "$f")" "$f" >> "$SIZES"; done
TRAILS_SHA_BEFORE=$(shasum -a 256 ~/.maltrail/trails.csv | cut -c1-64)

START=$(date +%s)
"$BASE/.venv/bin/python3" old/sensor.py -r "$PCAP" -c maltrail.local.conf --console --offline > "$RUNLOG" 2>&1
RC=$?
echo "RETURNCODE: $RC   (duration $(( $(date +%s) - START )) s)"

ls -la "$OUT" > "/tmp/after_${KEY}.txt"
echo "--- diff ls (before vs after):"
diff "/tmp/before_${KEY}.txt" "/tmp/after_${KEY}.txt"

: > "$OUT/$KEY.log.tmp"
for f in "$OUT"/[0-9]*.log; do
  old=$(awk -F'\t' -v p="$f" '$2==p{print $1}' "$SIZES"); old=${old:-0}   # new file -> 0
  new=$(stat -f%z "$f")
  if [ "$new" -gt "$old" ]; then
    tail -c +$((old + 1)) "$f" >> "$OUT/$KEY.log.tmp"
    echo "  +$((new - old)) bytes in $(basename "$f")"
  fi
done
mv "$OUT/$KEY.log.tmp" "$OUT/$KEY.log"
echo "New alert lines -> $OUT/$KEY.log : $(wc -l < "$OUT/$KEY.log")"

TRAILS_SHA_AFTER=$(shasum -a 256 ~/.maltrail/trails.csv | cut -c1-64)
echo "trails.csv sha256 before=$TRAILS_SHA_BEFORE after=$TRAILS_SHA_AFTER $([ "$TRAILS_SHA_BEFORE" = "$TRAILS_SHA_AFTER" ] && echo '(SAME)' || echo '(CHANGED!)')"
echo "--- [diag*] / error lines from the sensor output ($RUNLOG):"
grep -E "^\[diag|Traceback|Error|Exception|\[!\]|\[x\]" "$RUNLOG" | head -40
echo "--- last 5 lines of the sensor output:"
tail -5 "$RUNLOG"
