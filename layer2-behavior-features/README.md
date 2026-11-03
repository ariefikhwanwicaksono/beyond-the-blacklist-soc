# Layer 2 Experiment — Behaviour Profiling

> **STATUS (21 October 2026, evening): the methodology of the notebook in this folder is SUPERSEDED.**
> The notebook `layer2_feature_exploration.ipynb`, the README text below and all of `results/*.csv`
> document **Stage 1** — a test of 6 univariate features on 6 hosts, without UWF-ZeekData22 — which was
> **abandoned** because its results were weak (1 of 6 features "survived", with a thin margin,
> consistent with chance at such a small N). The methodology that APPLIES NOW (direction #12, "Stage 2":
> unsupervised Behaviour-Class clustering following Xu 2022, 8 hosts including 2 UWF-ZeekData22 hosts)
> is in:
>
> - **`compute_behavior_classes.py`** — a script, not a notebook; recomputes RU → 27 BCs directly from
>   the raw data (6 Zeek `conn.log` files + 2 UWF-ZeekData22 CSV shards). Its UWF inputs are built with
>   `prepare_uwf_filtered.sh`.
> - **`bc_results.json`** — the saved output of that script (per-host BC, pooled distribution, etc.) —
>   the source of truth for the BC clustering results table in the paper.
> - **Full methodology and final definitions**: the project's internal Layer 2 methodology framework
>   document (§3, especially §3.1 formula, §3.2 results, §3.2a independent-verification notes); it is not
>   part of this repository, and the paper's Methods section is its public version.
>
> The content below (original title, description and all following sections) is **kept as is as a
> historical record** — not deleted — because it explains what was tried and why it was not enough. Do
> not use the notebook or the CSVs in `results/` as a reference for the current methodology.

---

# (Original document below, Stage 1 — kept as a historical archive)

# Layer 2 Experiment (exploration) — 6 candidate behaviour features

Part of the research project "Scalability of Orchestration in a Security Operation Center"
(Kemdiktisaintek; originally targeted at ACIG). Entry point to Layer 2 of the 3-layer architecture:
computes 6 candidate behaviour features from the Zeek `conn.log` of the Experiment 2 pilot, enriched
with Maltrail alert history as an additional feature — **not** a clustering experiment *(note
21 Oct 2026: this is no longer accurate — clustering IS now the main Layer 2 methodology, see the status
banner at the top of this file)*. No algorithm, aggregation window or threshold is decided here; the
goal is purely to look at the real distributions before those design decisions are made.

## Host population & computation rules — version of 21 October 2026

The applicable methodology reference is the project's internal Layer 2 framework document (not included
here). This notebook implements its §2. Details are in section A.2 of the notebook.

- **Host = one machine, identified by its MAC.** IPs used by the same MAC are merged; gateway/NAT/`::`
  are dropped. The IP→MAC mapping is in `HOST_MANIFEST` and is re-checked automatically with
  `tcpdump -e` (10/10 OK).
- **Malware: 4 VMs, 3 independent infections.** zeus_vm_250 and zeus_vm_251 (same sample & C2; column
  `infection_group` = `x0proto_pair`), tinba_vm, dridex_vm. **zeus_vm_151 is excluded** (active for
  68.8 s, WS-Discovery/WSD only).
- **Benign: 2 external hosts**, CTU-Normal-32 (Kali, MAC `08:00:27:a3:83:43`) and CTU-Normal-33 (Win7,
  MAC `08:00:27:40:76:00`). The original Stratosphere pcaps were downloaded (SHA1 matches their
  `.capinfos`) and **re-processed with the same Zeek 8.2.2**; row and packet counts are identical to the
  Bro 2.5.1 logs shipped with the dataset.
- bittorrent/skype stay in the per-capture table only (synthetic, no host).
- **zeus uses the deduplicated pcap** (`data/pcap_derived/zeus_dedup.pcap`, script
  `../layer1-maltrail-zeek/tools/dedup_zeus_pcap.py`): 28,927 frames from MAC `78:e4:00:6c:39:cd` whose
  IP content is byte-identical to a VM frame were dropped. Validation: flow rows stay at 21,891,
  `resp_pkts` unchanged, `orig_pkts` 57,842 → 28,922, share of even `orig_pkts` 100% → 3.2%.
- **Two IPv6 rule variants, the same for all hosts** (`ipv6_rule`): `ipv4_only` and `ipv4_plus_ipv6`.
  The final choice is item #16.
- **`maltrail_alert_count` = NaN for CTU-Normal** (never scanned by Maltrail at the time), not 0.
- **Uniform 5-minute windows** for the stability analysis (section H) and the range check (section I);
  SD for `bytes_ratio_log2`/`dst_port_entropy`/`direction_ratio`, CV for positive features.
- Checksums of all pcaps: `../layer1-maltrail-zeek/data/pcap_raw/CHECKSUMS.tsv`.

## Prerequisites

This notebook must sit **next to** `layer1-maltrail-zeek/` (in the same parent folder), and
`layer1-maltrail-zeek/layer1_experiment.ipynb` must **have run successfully** — this notebook reads
`data/zeek_out/<key>/conn.log` and `data/maltrail_out/<key>.log` from that folder; it does not download
or run anything itself.

## How to use

1. Use the same venv as `layer1-maltrail-zeek/.venv` (only `pandas` and `numpy` are needed, both already
   there) — or a new venv if you prefer to keep it separate:

   ```bash
   pip install pandas numpy
   ```

2. Open `layer2_feature_exploration.ipynb` in VS Code and select the same kernel.
3. Run the cells one by one from top to bottom.

## The six features (full definitions in the markdown cell of section D of the notebook)

1. `bytes_ratio_log2` — log2 ratio of total bytes sent vs received per host.
2. `dst_port_entropy` — Shannon entropy of the distribution of destination ports contacted by the host.
3. `interarrival_cv` — coefficient of variation of the gaps between connections (a candidate *beaconing*
   indicator).
4. `n_unique_dst` — number of unique (destination IP, port) pairs contacted.
5. `avg_duration_sec` — mean flow duration.
6. `direction_ratio` — proportion of flows in which the host sends more packets than its peer.

Plus `maltrail_alert_count` and `maltrail_ever_alerted` (Maltrail history as a feature, following the
*cold-start contamination* resolution in the project notes — not a pass/fail gate).

## Verification status

The parsing logic (`parse_zeek_log`, `parse_maltrail_log`, the Maltrail log regex) is copied **exactly**
from sections C.4/D.2 of `layer1_experiment.ipynb`, which were verified empirically along two paths (see
that folder's README) — deliberately not rewritten differently. The computation of the 6 features was
first tested with `jupyter nbconvert --execute` in a sandbox using **synthetic** `conn.log`/Maltrail logs
(identical format, made-up content) to rule out syntax/logic bugs — including edge cases such as a host
whose `interarrival_cv` should be low for an artificial periodic pattern. *Update 17 Oct 2026*: the
notebook has been run on the real pilot data, and all six features for 5 hosts were recomputed
independently from `conn.log` by a reviewer — the results match `results/host_features_pilot.csv`
exactly.

## What this notebook deliberately does NOT decide

- **The final aggregation unit** (per host vs per pcap vs time window) — section D uses per host as the
  basic unit and section E compares it with per pcap, but both are only options, not a final decision.
- **Per-host ground truth** — the `malware`/`benign` labels used are purely per PCAP, carried as they
  are to each host inside it. After the population was cleaned, only Zeus has more than one host
  (3 VMs). .151 shows no C2 traffic, so the "malware" label for it is probably wrong — not yet decided.
- **The clustering algorithm** and **the validation/class-imbalance strategy** — not chosen at all.
- **The exact definition of `direction_ratio`** relative to Qu et al. 2015 — the operationalisation in
  this notebook is literal (proportion of `orig_pkts > resp_pkts`), not yet matched to that paper's
  original definition.

## Design guidance from Arief (28 August 2026) — NOT yet executed

Recorded here so it does not get lost before this notebook is actually re-run (see the staleness note
below).

**Delta/self-referential features**: Arief has shown in his own separate research (CERT r6.2 insider
threat) that DELTA features — the change/deviation relative to the entity's own baseline across time
windows, rather than a single snapshot — work well. This is CONSISTENT with the existing design guidance
in `../layer1-maltrail-zeek/layer1-layer2-analogy.md` ("whether a resident's habits are STABLE from one
time window to the next, or jump around"). [MEDIUM CONFIDENCE — the methodological direction is strong,
BUT there is a time-scale gap to resolve first rather than adopting it as is]: CERT r6.2 has 76 weeks of
continuous logs per user, so week-to-week deltas are meaningful; our Layer 1 pilot pcaps are a SINGLE
capture per pcap (much shorter, not a continuous per-host log across days/weeks). If delta features are
used here, the "time window" has to be adapted to the pcap scale (windows of a few minutes INSIDE one
pcap, as in the existing guidance), not CERT r6.2's weekly scale — an explicit design decision not yet
taken, which changes the aggregation unit to per-host-per-time-window (not just per host or per pcap as
in the options above).

**Clustering algorithm — empirical ablation, do not force it**: it was agreed NOT to pick a single
algorithm up front; run an ablation adapted to the character of the real data. Two-step clustering (in
the spirit of magnitude + relational, similar to Arief's other research) is on the candidate list, BUT
this decision explicitly CANNOT be taken yet: (a) this notebook had never been run on the REAL pilot data
from the fixed Layer 1 — the `layer2_feature_exploration.html` in this folder was dated 25 August 04:32
UTC, BEFORE the file-discovery fix (26 August) and the trails.csv fix+pin (28 August) — so it had to be
considered INVALID and needed a full re-run; (b) N=6 pilot pcaps (3 malware/2 benign/1 IoT botnet) is
probably too small for a robust clustering ablation — a methodological risk to be accounted for
explicitly, not assumed to be sufficient.

*Update 17 Oct 2026*: the notebook was fully re-run (`nbconvert --execute`) against the existing Layer 1
`conn.log`/Maltrail logs (mtime 28 August), after the host-population changes above; the `.html` and both
CSVs in `results/` were updated as well. Point (a) on staleness no longer applies. Point (b) became even
more serious: the per-host table effectively contains only 5 VMs from 3 malware pcaps, with no benign
class.

*Update 21 Oct 2026 (evening)*: the clustering-algorithm decision above **has been taken** — not as an
ablation of the candidates in this paragraph, but by following the Behaviour-Class framework (RU/entropy,
Xu 2022 Ch. 3) directly without an additional ablation, because the architectural argument (Layer 2 must
be unsupervised because the rule-based Layer 1 never produces labels) is stronger than a purely empirical
algorithm choice. See §0 and §3.1 of the internal Layer 2 framework document.

## After running this notebook

Read section G (summary) of the notebook for the suggested order of work. In short: discuss the
aggregation unit and ground-truth granularity (probably with input from Dedy/Ashari) before adding pcaps
or choosing a clustering algorithm — to avoid rework if those decisions change after the corpus grows.

*(Note 21 Oct 2026: this order of work has been superseded by the direction #12 decision — see the banner
at the top of this file. Kept as an archive, not an active reference.)*

## Folder structure

```
compute_behavior_classes.py   # CURRENT METHODOLOGY (direction #12) -- see the banner at the top of this file
prepare_uwf_filtered.sh       # builds the UWF inputs of compute_behavior_classes.py from the UWF CSV shards
UWF_SHARDS.sha256             # SHA-256 of the six UWF-ZeekData22 CSV shards used
bc_results.json               # output of the script above; source of the BC clustering table in the paper
eps_sensitivity_sweep.py      # epsilon sensitivity sweep -> results/eps_sensitivity_sweep.json
make_bc_distribution_figure.py  # BC distribution figure from bc_results.json
layer2_feature_exploration.ipynb / .html   # Stage 1 (superseded), see the banner
results/
  eps_sensitivity_sweep.json  # output of eps_sensitivity_sweep.py (Stage 2)
  host_features_pilot.csv     # one row per (ipv6_rule, capture, host_id): 6 hosts x 2 variants -- Stage 1
  pcap_features_pilot.csv     # one row per capture (all flows) -- coarse comparison -- Stage 1
  window_features_5min.csv    # one row per (ipv6_rule, host, full 5-minute window); column `valid` = >=10 flows -- Stage 1
  window_stability_5min.csv   # per (ipv6_rule, host): number of windows, median/P10/P90, SD or CV per feature -- Stage 1
  range_check_5min.csv        # per (ipv6_rule, feature): malware range, range_to_within, window overlap -- Stage 1
```
