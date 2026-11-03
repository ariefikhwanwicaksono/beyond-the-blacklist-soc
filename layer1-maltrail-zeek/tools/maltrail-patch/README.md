# Maltrail patches used in the experiments

The experiments ran the Python sensor `old/sensor.py` of [Maltrail](https://github.com/stamparm/maltrail)
(MIT license) in offline pcap-replay mode. The Rust sensor did not build on macOS arm64 at the time.
Instead of vendoring the whole Maltrail repository, this folder holds:

| File | Content |
|---|---|
| `UPSTREAM_COMMIT.txt` | Upstream commit the patch applies to: `7ea90920fe98077cb1fd4b6a6734a495c2d4fcd6` (2026-08-24) |
| `maltrail_patches.diff` | `git diff` of our changes to `core/log.py` and `old/sensor.py` |
| `maltrail.local.conf` | Sensor configuration used for all runs (`--offline`, `PROCESS_COUNT 1`, `DISABLE_CHECK_SUDO true`) |

## Install

```bash
git clone https://github.com/stamparm/maltrail.git layer1-maltrail-zeek/tools/maltrail
cd layer1-maltrail-zeek/tools/maltrail
git checkout 7ea90920fe98077cb1fd4b6a6734a495c2d4fcd6
git apply ../maltrail-patch/maltrail_patches.diff
cp ../maltrail-patch/maltrail.local.conf .
# edit LOG_DIR in maltrail.local.conf to the absolute path of ../../data/maltrail_out
```

Checked on 2026-11-03: the diff applies cleanly to that commit. The resulting `core/log.py` is
byte-identical to the file used in the experiments. The resulting `old/sensor.py` has identical code
(compared via the Python AST): only its comments and two diagnostic messages were translated into
English for this publication.

## What the patches do

All changes are confined to offline replay. Live sensing is unchanged. Details are in
`../../README.md`, which is in Indonesian.

- **Offline timestamp:** alerts and the per-second event throttle use the packet timestamp from the pcap
  instead of wall-clock time. This makes runs deterministic.
- **Relative-timestamp fallback:** for pcaps whose timestamps start near the Unix epoch (tinba, dridex,
  CTU-Normal), the sensor adds a fixed offset of 631152000 s (1990-01-01) instead of falling back to wall
  clock. Alerts from these pcaps are written to `1990-01-01.log`.
- **Diagnostic counters:** `[diag]`, `[diag-v2]` and `[diag-v3]` lines are printed at the end of each
  offline run. Examples are in `../../data/maltrail_out/_run_*_console.txt`.

## Trail set: important for reproducing alert counts

Alert counts depend on the trail set (`~/.maltrail/trails.csv`). That file aggregates 38 third-party
feeds and changes daily. The experiments used a snapshot frozen on 2026-08-28. Its SHA-256 hashes are in
`../../trails_snapshots/MANIFEST_trails_2026-08-28T0152Z.txt`.

The snapshot itself is **not** redistributed, because it is third-party feed content, and it cannot be
rebuilt from the feeds today. Running Maltrail now therefore uses a different trail set, and alert counts
may differ.

Two pitfalls if you have the snapshot:

- **Rebuild on start-up.** `old/sensor.py` rebuilds `trails.csv` from the static trails (without feeds)
  whenever the file is older than `UPDATE_PERIOD` (24 h). This happens even with `--offline`.
- **Use the pinning script.** `../pin_trails_fresh.py` restores the snapshot, verifies SHA-256, clears the
  binary cache and refreshes the mtime. Run it right before the sensor.

With that procedure, a re-run on 2026-10-22 reproduced the original tinba result exactly: 10,902 alerts
with identical content (`../../data/maltrail_out/_control_tinba_20261022.log`).
