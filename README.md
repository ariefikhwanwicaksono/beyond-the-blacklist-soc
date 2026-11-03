# Beyond the Blacklist: code and results

Code, executed notebooks and result files for the paper:

> **Beyond the Blacklist: A Three-Layer SOC Architecture for Behavioural Profiling and MITRE ATT&CK-Grounded Alert Escalation**
> Dedy Hariyadi, Arief Ikhwan Wicaksono, Ahmad Ashari.

> [!IMPORTANT]
> **Usage notice.** This code is under active development and is shared for transparency and
> reproducibility. Please do not use this code, its results or its derived data in any manuscript
> submitted for publication. The authors will use this work in their own forthcoming publications.

The architecture has three layers:

1. **Layer 1:** blacklist (Maltrail) and flow monitoring (Zeek) in parallel.
2. **Layer 2:** per-host behavioural profiling from Zeek `conn.log`, using Maltrail alert history as a feature, not a gate.
3. **Layer 3:** a MITRE ATT&CK knowledge graph (Neo4j) used to ground escalation.

Experiment 3 connects Layer 2 behaviour classes to Layer 3 graph inspection.

Notebooks are committed **with their outputs**, as a record of the executed runs. There are two exceptions:
`layer1_experiment.ipynb` (its run results are in `layer1-maltrail-zeek/results/RESULTS.md`) and
`explore_kg.ipynb` (it needs your own Neo4j instance). All notebooks, scripts and notes have been
translated into English. The notebooks with outputs were re-executed after translation, and they gave the
same numerical results.

## Repository layout

| Folder | Layer / experiment | Entry points | Key results |
|---|---|---|---|
| `layer1-maltrail-zeek/` | Layer 1 | `layer1_experiment.ipynb`, `layer1_vs_uwf_heuristics.ipynb`, `make_layer1_alertcounts_figure.py`, `tools/` | `results/`, `data/maltrail_out/` (alert logs), `data/pcap_raw/CHECKSUMS.tsv` |
| `layer2-behavior-features/` | Layer 2 | `layer2_feature_exploration.ipynb`, `prepare_uwf_filtered.sh`, `compute_behavior_classes.py`, `eps_sensitivity_sweep.py`, `make_bc_distribution_figure.py` | `bc_results.json`, `results/*.csv`, `results/eps_sensitivity_sweep.json` |
| `layer3-attck-neo4j/` | Layer 3 | `fetch_attck.py`, `parse_attck.py`, `load_neo4j.py`, `explore_kg.ipynb`, `save_results_summary.py`, `build_cooc_graph.py`, `build_final_figure.py` | `results/attck_cooccurrence_topology_results.json`, `results/neo4j_verification_log*.md`, `data/csv/` |
| `experiment3-graph-inspection/` | Experiment 3 | `experiment3_graph_inspection.ipynb` (built and executed by `build_experiment3_nb.py` / `execute_experiment3_nb.py`), `experiment3_prototype.py` | `results/experiment3_window_results.json`, `results/summary.md` |
| `verification/` | Dataset and identity checks | see `verification/README.md` | — |

## Data: not included, obtain from the original sources

No raw traffic is redistributed. The pcaps, Zeek logs derived from them, and dataset shards stay under
their original terms. Download them from the sources below, place them at the indicated paths, and check
them against `layer1-maltrail-zeek/data/pcap_raw/CHECKSUMS.tsv` (MD5/SHA-1/SHA-256). Paths are
relative to `layer1-maltrail-zeek/data/`.

| Capture (paper label) | Source | Place as |
|---|---|---|
| RAT/x0Proto pair (dataset label "Zeus") | USTC-TFC2016, `Malware/Zeus.pcap`: <https://github.com/yungshenglu/USTC-TFC2016> (MPL-2.0) | `pcap_raw/zeus.pcap` |
| Tinba | USTC-TFC2016, `Malware/Tinba.pcap` | `pcap_raw/tinba.pcap` |
| BitTorrent, Skype (synthetic, per-capture table only) | USTC-TFC2016, `Benign/BitTorrent.pcap`, `Benign/Skype.pcap` | `pcap_raw/bittorrent.pcap`, `pcap_raw/skype.pcap` |
| Dridex | Stratosphere CTU-Malware-Capture-Botnet-153-1, `2016-02-12-capture_win4.pcap`: <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-153-1/> | `pcap_raw/dridex.pcap` |
| IoT-23 scenario 1-1 | Stratosphere/Aposemat IoT-23, `2018-05-09-192.168.100.103.pcap`: <https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/> (cite Garcia et al. 2020, doi:10.5281/zenodo.4743746) | `pcap_raw/iot23_capture1.pcap` |
| Benign host CTU-Normal-32 | <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-32/> `2017-05-02_normal.pcap` (+ `.binetflow`) | `ctu_normal32/raw/` |
| Benign host CTU-Normal-33 | <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-33/> `capture-new-Windows-7-Full.pcap` (+ `.binetflow`) | `ctu_normal33/raw/` |
| CTU-13 scenario 42 (rejected source, `verification/` only) | <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/> `capture20110810.truncated.pcap.bz2`, `detailed-bidirectional-flow-labels/capture20110810.binetflow` | `ctu13_botnet42/raw/` |
| UWF-ZeekData22 hosts 143.88.5.12, 143.88.7.10 | <https://datasets.uwf.edu> (Bagui et al., *Data* 8(1):18, 2023); the six CSV shards used are listed with SHA-256 in `layer2-behavior-features/UWF_SHARDS.sha256` | `<repo root>/dataset/` |
| MITRE ATT&CK Enterprise v19.2 | `fetch_attck.py` downloads `enterprise-attack-19.2.json` from <https://github.com/mitre-attack/attack-stix-data> (SHA-256 `dc1639ca…c3d8f4`) | `layer3-attck-neo4j/data/` |

Stratosphere `.capinfos` files with the publisher's own SHA-1/MD5 for the Dridex and CTU-Normal pcaps are
in `layer1-maltrail-zeek/data/provenance/`. The local copies match them.

## Reproducing each layer

Environment used:

- macOS arm64, Python 3.9 with `pandas` 2.3, `numpy` 2.0 and `pcapy-ng` 2.1
  (`requirements.txt` in each folder).
- Zeek 8.2.2.
- Maltrail `old/sensor.py` at upstream commit `7ea90920` plus our patch
  (`layer1-maltrail-zeek/tools/maltrail-patch/`).
- Neo4j 5.x.
- Graphviz `sfdp`, for `build_final_figure.py` only.

**Layer 1**

1. **Zeek.** Run `zeek -C -r <pcap> local` inside `data/zeek_out/<key>/` for each capture.
2. **Zeus duplicate frames.** The Zeus pcap contains duplicated outbound frames. Create
   `data/pcap_derived/zeus_dedup.pcap` with `python3 tools/dedup_zeus_pcap.py data/pcap_raw/zeus.pcap data/pcap_derived/zeus_dedup.pcap`,
   then run Zeek on it into `data/zeek_out/zeus_dedup/`. Expected checksum: `CHECKSUMS.tsv`.
3. **Maltrail.** Install Maltrail as described in `tools/maltrail-patch/README.md`, then run it per pcap
   with `tools/run_maltrail_pcap.sh <key> <pcap>`.
   - Alert counts depend on the trail snapshot of 2026-08-28. The snapshot cannot be redistributed or
     regenerated; see that README. The alert logs produced in our runs are therefore included under
     `data/maltrail_out/`.
4. **Notebooks.** `layer1_experiment.ipynb` documents the full Layer 1 run, including download and
   integrity checks. `layer1_vs_uwf_heuristics.ipynb` reads the UWF shards from `<repo root>/dataset/`.
   - **Where the executed record of `layer1_experiment.ipynb` lives.** The `.ipynb` was last edited after
     its final run (2026-10-22) and is stored without outputs. The results of the runs are in
     `results/RESULTS.md` (zeus 5,697 and tinba 10,902 alerts, the determinism checks and the
     CTU-Normal runs). Each figure there can be checked against the raw logs in `data/maltrail_out/`.

**Layer 2**

1. **Per-host feature tables.** `layer2_feature_exploration.ipynb` needs the Zeek outputs above
   (`zeus_dedup`, `tinba`, `dridex`, `bittorrent`, `skype`, `ctu_normal32`, `ctu_normal33`). It writes
   `results/host_features_pilot.csv`, `window_*_5min.csv` and `range_check_5min.csv`.
2. **Behaviour classes (`bc_results.json`).**
   - Run `./prepare_uwf_filtered.sh <repo root>/dataset`, then `python3 compute_behavior_classes.py`.
   - Input and output paths can be overridden with `PFR_ZEEK_OUT`, `UWF_FILTERED_DIR` and `BC_RESULTS_OUT`.
   - Checked on 2026-11-03: this reproduces the committed `bc_results.json` byte for byte.
3. **Downstream scripts.** `eps_sensitivity_sweep.py` reproduces `results/eps_sensitivity_sweep.json`
   byte for byte.

**Layer 3 (ATT&CK knowledge graph)**

1. Run `python3 fetch_attck.py`, then `python3 parse_attck.py`. This writes `data/csv/`, which is included.
2. Run `python3 load_neo4j.py` with the `NEO4J_URI`, `NEO4J_USER` and `NEO4J_PASSWORD` environment variables.
   `explore_kg.ipynb` is a read-only query notebook. It is stored without outputs because it needs your own
   Neo4j instance. Run it after `load_neo4j.py`; it reads the same environment variables.
3. Run `save_results_summary.py` to write `results/attck_cooccurrence_topology_results.json`.
   - Its content is identical across runs.
   - The order of equal-size components can differ between runs, because Python set iteration order is
     hash-seed dependent.

**Experiment 3**

1. Run `experiment3_graph_inspection.ipynb` from inside its folder, or run
   `PFR_BASE=<repo root> python3 experiment3_prototype.py`.
2. The prototype also reads `tools/maltrail/core/settings.py`, which requires the Maltrail install above.
3. Checked on 2026-11-03: the prototype reproduces the committed `experiment3_window_results.json` and
   `summary.md` byte for byte.

## Known non-determinism

- **Maltrail's "potential web scanning" heuristic.** On repeated runs it selects different triggering
  packets, but the per-host **count** is stable (CTU-Normal-32: 123 alerts in 3/3 runs; CTU-Normal-33: 13
  in 4/4). All non-heuristic alerts are identical across runs. See
  `data/maltrail_out/_determinism_check_*`.

## License

- **Code:** MIT, see `LICENSE`.
- **Maltrail patch:** derived from Maltrail (MIT, © Maltrail developers).
- **ATT&CK-derived files** (`layer3-attck-neo4j/data/csv/`, graph results): subject to MITRE's ATT&CK
  terms of use; see `NOTICE-ATTACK.md`.
- **Datasets:** not redistributed; each remains under its publisher's terms.

## Citation

Citation TBD. Until a publication is available, please cite this repository and the paper title above,
and see the usage notice at the top of this README.
