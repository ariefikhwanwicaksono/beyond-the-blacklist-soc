"""Pin Maltrail's trails.csv to the frozen snapshot AND refresh its mtime, so old/sensor.py does not rebuild the trails.

Why this is needed (found 22 Oct 2026): core/update.py::update_trails() rebuilds trails.csv when it is
>= UPDATE_PERIOD (86400 s) old or when a static trail file is newer. In --offline mode that rebuild uses the
static trails ONLY (no feeds) -> the content differs from the snapshot. pin_trails_from_snapshot() in the
Layer 1 notebook uses shutil.copy2, which keeps the snapshot's mtime (28 August), so from 29 August on that pin
was no longer effective. This script: verify snapshot SHA-256 vs manifest -> copy -> remove the .bin/.bin.lock
cache -> touch (content unchanged, only mtime = now) -> verify the live SHA-256. Run it RIGHT BEFORE running
the sensor (24-hour safe window), and check the SHA-256 again after the run.

Usage: python3 -I pin_trails_fresh.py [STAMP]   (default 2026-08-28T0152Z)
"""
import hashlib
import os
import re
import shutil
import sys
import time
from pathlib import Path

STAMP = sys.argv[1] if len(sys.argv) > 1 else "2026-08-28T0152Z"
HERE = Path(__file__).resolve().parent
SNAP = HERE.parent / "trails_snapshots"
HOME = Path.home() / ".maltrail"
FILES = ["trails.csv", "trails.csv.confidence"]


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


manifest = (SNAP / f"MANIFEST_trails_{STAMP}.txt").read_text()
expected = {}
for name in FILES:
    m = re.search(rf"^\s*{re.escape(name)}:\s+([0-9a-f]{{64}})\s*$", manifest, re.M)
    if not m:
        sys.exit(f"FAILED: sha256 for {name} not found in manifest")
    expected[name] = m.group(1)

for name in FILES:
    src = SNAP / f"trails_{STAMP}_frozen.csv{name[len('trails.csv'):]}"
    if sha256(src) != expected[name]:
        sys.exit(f"FAILED: snapshot {src.name} is corrupt (sha256 does not match manifest) -- live files untouched")

for name in FILES:
    shutil.copyfile(SNAP / f"trails_{STAMP}_frozen.csv{name[len('trails.csv'):]}", HOME / name)
for cache in ("trails.csv.bin", "trails.csv.bin.lock"):
    if (HOME / cache).exists():
        (HOME / cache).unlink()
now = time.time()
for name in FILES:
    os.utime(HOME / name, (now, now))

for name in FILES:
    got = sha256(HOME / name)
    if got != expected[name]:
        sys.exit(f"FAILED: post-pin verification of {name}: {got}")
    print(f"pinned {name}: sha256 {got[:16]}... mtime now")
print(f"OK -- run the sensor within 24 h (before {time.strftime('%Y-%m-%d %H:%M', time.localtime(now + 86400))})")
