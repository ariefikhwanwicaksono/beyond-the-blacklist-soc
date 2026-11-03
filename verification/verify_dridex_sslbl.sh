#!/bin/bash
# Check the TLS certificates in the dridex capture against the abuse.ch SSL Blacklist (SSLBL).
# Paper claim: 3 of the 5 certificates (SHA-1 d1c74082..., 1c8357ec..., 77b66d0d...) are listed as "Dridex C&C",
# with listing dates 2016-01-11..18, inside the capture period (2016-01-14..02-12).
# SSLBL is a live list; entries can change over time. Checked 2026-10-20 and 2026-11-03.
#
# Usage: verify_dridex_sslbl.sh <path/to/dridex.pcap>
set -eu
PCAP="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
( cd "$WORK" && zeek -C -r "$PCAP" "$HERE/cert_sha1.zeek" > certs.txt )
curl -s --max-time 60 -o "$WORK/sslblacklist.csv" https://sslbl.abuse.ch/blacklist/sslblacklist.csv
echo "certificates in pcap: $(wc -l < "$WORK/certs.txt")"
while IFS='|' read -r sha1 sha256 subject; do
  hit=$(grep -i ",$sha1," "$WORK/sslblacklist.csv" || true)
  echo "$sha1  $subject  ->  ${hit:-not listed}"
done < "$WORK/certs.txt"
