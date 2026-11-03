# Layer 1 run results (Maltrail + Zeek)

`layer1_experiment.ipynb` is stored without outputs. The notebook was edited after its final run, and its
earlier HTML export was in Indonesian. This file records the executed results instead. Every alert count
below can be checked against the raw Maltrail logs in `../data/maltrail_out/` (one alert per line).

All Maltrail runs used the patched `old/sensor.py` (see `../tools/maltrail-patch/`), `PROCESS_COUNT 1`,
`--offline`, and the trail snapshot `2026-08-28T0152Z` (see `../trails_snapshots/`).

## Pilot corpus (run of 28 August 2026)

| pcap | ground truth | Zeek flows (`conn.log`) | Maltrail alert lines | unique observables | log |
|---|---|---:|---:|---:|---|
| zeus | malware | 22,053 | 5,697 | 11 | `zeus.log` |
| tinba | malware | 10,813 | 10,902 | 1,001 | `tinba.log` |
| dridex | malware | 9,384 | 0 | 0 | none (no alerts) |
| bittorrent | benign | 7,517 | 0 | 0 | none (no alerts) |
| skype | benign | 6,321 | 0 | 0 | none (no alerts) |
| iot23_capture1 | malware | 1,008,748 | 5 | 5 | `iot23_capture1.log` |

The same table, as written by Section E of the notebook, is in `pilot_summary_layer1.csv`. The `family`
label of `iot23_capture1` in that CSV has been translated from Indonesian. No other value was changed.

## Determinism checks

| check | date | runs | alert lines per run | logs |
|---|---|---:|---|---|
| zeus, repeated runs (Section C.5) | 28 Aug 2026 | 5 | 5,697 in every run | `_determinism_check_zeus_run{1..5}.log`, `_determinism_check_run{1..5}.log` |
| tinba, repeated runs (Section C.5) | 28 Aug 2026 | 5 | 10,902 in every run | `_determinism_check_tinba_run{1..5}.log` |
| tinba positive control, after the trail-pin fix | 22 Oct 2026 | 1 | 10,902, byte-identical to `tinba.log` | `_control_tinba_20261022.log` |

## Benign CTU-Normal captures (run of 22 October 2026)

| capture | Maltrail alert lines | runs | logs |
|---|---:|---:|---|
| CTU-Normal-32 | 123 | 3 | `ctu_normal32.log`, `_determinism_check_ctu_normal32_run{2,3}.log` |
| CTU-Normal-33 | 13 | 4 | `ctu_normal33.log`, `_determinism_check_ctu_normal33_run{2,3}.log` |

The per-capture count was the same in every run. Maltrail's "potential web scanning" heuristic picks
different triggering packets from run to run, so those lines can differ while the count stays the same.
All non-heuristic alerts are identical across runs. CTU-Normal-33 had 4 runs, but only 3 logs are
stored. The console output of the first run of each capture is in `_run_ctu_normal{32,33}_console.txt`.
