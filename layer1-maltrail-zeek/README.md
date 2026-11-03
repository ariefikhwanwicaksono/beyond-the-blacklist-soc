# Layer 1 Experiment — Maltrail + Zeek

Part of the research project "Scalability of Orchestration in a Security Operation Center"
(Kemdiktisaintek; originally targeted at ACIG). Tests Layer 1 of the 3-layer architecture: Maltrail
(rule-based) + flow monitoring (Zeek) running in parallel at the same port-mirroring point.

> **Note for readers of the public repository.** This README is the project's chronological working log,
> translated into English. It records the verification history (including bugs found and fixed) because
> that history matters for the reproducibility statements in the paper. References to a "development
> sandbox" mean the cloud environment in which the notebooks were first drafted and dry-run; "the
> authors' Mac" is where all reported runs were executed. The Maltrail installation for this repository
> is described in `tools/maltrail-patch/README.md`.

## How to use

1. Create a new venv (recommended to keep it **separate** from any older Python 3.9 environment — the
   dependencies of this experiment, especially `pcapy-ng`, are safer in their own venv):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   pip install pcapy-ng
   ```

2. Open `layer1_experiment.ipynb` in VS Code and select the kernel from the `.venv` above.

3. Run the cells one by one from top to bottom. The recipe of section C (Maltrail) **has been verified
   empirically TWICE** — first manually in a terminal (24 August 2026), then again through this notebook
   itself (`layer1_experiment.ipynb`, second run on the authors' Mac, 24 August 2026), with results that
   match both runs exactly. There is no longer any need to fill in variables manually or guess CLI flags.
   Read the status table in the second markdown cell of the notebook for per-component details and
   confidence levels, and the "Notebook verification history" section below for the full chronology.

4. Install the required external tools (outside `requirements.txt`, because they are not Python
   packages):
   - **Zeek**: `brew install zeek` (installed & confirmed on the authors' Mac, v8.2.2)
   - **Maltrail**: `git clone https://github.com/stamparm/maltrail.git tools/maltrail` — the sensor used
     by this notebook is `tools/maltrail/old/sensor.py` (Python), **not** the official Rust sensor
     (`tools/maltrail/sensor/`), because the latter fails to build on macOS arm64. For this repository,
     check out the pinned commit and apply our patch as described in `tools/maltrail-patch/README.md`.
   - **7-Zip** (optional, only to open `Cridex.7z`/`Shifu.7z`): `brew install sevenzip` or
     `brew install p7zip`

## Verification status (summary — full details & confidence labels are in the first markdown cell of the notebook)

- Pilot dataset (USTC-TFC2016: Zeus, Tinba, BitTorrent, Skype; Stratosphere: Dridex) — **verified
  byte-exact**; all 5 downloaded and matching.
- Sensor: `old/sensor.py`, flags `-r/-c/--console/--offline` — **verified directly via `--help`**.
- The root check is skipped through `DISABLE_CHECK_SUDO true` (an official upstream config option), NOT
  `sudo` — a deliberate least-privilege decision (the packet parser does not need to run as root in `-r`
  mode).
- Alert log format & trail cache (`~/.maltrail/trails.csv`, 38 feeds + custom + static, NOT 57 as in an
  early draft of this research) — **verified empirically**, see the parser regex in section C.4.
- **Pilot results for the 5 pcaps — confirmed twice, matching each other exactly**: Zeus & Tinba (malware)
  → alerts; Dridex (malware) → 0 alerts (possible IOC staleness, NEEDS FURTHER VERIFICATION); BitTorrent &
  Skype (benign) → 0 alerts. Full details in section E, verification chronology below.

## Notebook verification history (important for the reproducibility notes in the paper)

Recorded here explicitly because it is a methodological lesson relevant to the methodology/
reproducibility section of the journal paper, not just internal debugging notes.

**Run 1 — manually in a terminal (24 August 2026).** The Maltrail CLI recipe (`old/sensor.py -r <pcap>
-c maltrail.local.conf --console [--offline]`, `DISABLE_CHECK_SUDO true`, etc.) was verified step by step
directly in a terminal on the Mac, outside the notebook, until all five pilot pcaps produced sensible
output. The results of this run became the reference/ground truth for comparison:

| pcap | ground truth | Maltrail result |
|---|---|---|
| Zeus | malware | ALERT — `"blackshades (malware)"` + several heuristics, 1002 log lines |
| Tinba | malware | ALERT — 500+ `.xyz` DGA domains, all `(static)`, 1002 log lines |
| Dridex | malware | 0 alerts — possible IOC staleness (2016 pcap vs 2026 blacklist), **NEEDS FURTHER VERIFICATION** |
| BitTorrent | benign | 0 alerts |
| Skype | benign | 0 alerts |

**Run 2 — recipe embedded in the notebook, first run on the Mac (24 August 2026) → COMPLETE FAILURE.**
All five Maltrail runs in section C of the notebook failed with `returncode=1`, stderr
`please install 'pcapy or pcapy-ng'` — although `pcapy-ng` was installed. Root cause: the notebook code
called `sensor.py` via `sys.executable`, and in the Jupyter/VS Code kernel used, `sys.executable` turned
out to resolve to the **system** Python (`/Library/Developer/CommandLineTools/usr/bin/python3`), not to
the experiment folder's `.venv` — even though the `.venv` kernel had been selected explicitly in VS Code.
As a result all five pcaps produced "0 alerts", including Zeus and Tinba, which **definitely** produced
alerts in Run 1. This is not a cosmetic bug: had it gone unnoticed, those "0 alerts" could have been
written in the paper as valid negative detection results, while they were purely an execution failure
disguised as a result. (Zeek in section D, by contrast, fully succeeded in this run — 5/5 `conn.log`
files were created — because it does not go through `sys.executable`.)

**Fix.** The notebook was changed to (1) look explicitly for `BASE_DIR/.venv/bin/python3` first (only then
falling back to `sys.executable`, with a clearly printed warning if the fallback is used), and (2) run a
preflight `import pcapy` with the resolved interpreter before the 5-pcap loop starts, so that a dependency
failure stops with a clear message instead of masquerading as "0 alerts" x5.

**Run 3 — the fixed notebook, re-run on the Mac (24 August 2026) → SUCCESS, matching Run 1 exactly.**

| pcap | returncode | alert lines | vs. Run 1 |
|---|---|---|---|
| Zeus | 0 | 16 | match (alert) |
| Tinba | 0 | 1002 | **exact match**, 1002 = 1002 lines |
| Dridex | 0 | 0 | match (0 alerts) |
| BitTorrent | 0 | 0 | match (0 alerts) |
| Skype | 0 | 0 | match (0 alerts) |

The exact match of Tinba's line count (not just "both have alerts") is strong evidence that the notebook
now really calls `sensor.py` through the right interpreter with the same trail snapshot.
`pilot_summary_layer1.csv` (section E) is now generated automatically by this notebook run, not typed
manually from terminal results.

**Limitations still open**: `n_zeek_flows` per pcap (Zeus=22053, Tinba=10813, Dridex=9384,
BitTorrent=7517, Skype=6321, from the notebook run above) has no independent comparison yet — so far it is
only verified as "non-zero and the pipeline runs cleanly", not "the numbers are quantitatively plausible".
The IOC-staleness hypothesis for Dridex is also still [MEDIUM CONFIDENCE], not investigated further.

## Folder structure (created automatically by the notebook)

```
data/
  pcap_raw/         # downloaded pcaps (not included in the public repository; see CHECKSUMS.tsv)
  pcap_extracted/   # extracted .7z content (Cridex, Shifu — optional)
  maltrail_out/     # Maltrail alert logs, one .log file per pcap (e.g. zeus.log, tinba.log)
  zeek_out/<key>/   # conn.log etc. per pcap
results/
  pilot_summary_layer1.csv
tools/
  maltrail/         # clone of the Maltrail repository (not shipped; clone it yourself) — including
                    # the maltrail.local.conf created automatically by the notebook (section C.2)
```

## After this pilot runs

The Layer 1 pipeline (download dataset → Maltrail → Zeek → summary) is fully reproducible from this
notebook, not only from a manual terminal — see the checklist in the last markdown cell of the notebook
(section E) for the full version. Next priorities, in concrete order:

1. Investigate the IOC-staleness hypothesis for the 0-alert Dridex result (2016 pcap vs 2026 blacklist
   snapshot) — not done yet; this decides whether the Dridex result is written as a "clean negative case"
   or as a "methodological limitation that needs explaining".
2. (Optional) scale to Cridex/Shifu, find a valid Ursnif pcap.
3. Move on to the Layer 2 experiment (extracting 6 candidate behaviour features from `conn.log`, enriched
   with the Maltrail alert history).

## Additional dataset (25 August 2026) — broader malware-family coverage

The manifest now has two parts: `PILOT_MANIFEST` (the original 5 pcaps, NOT changed at all — verified
along two paths, see "Notebook verification history" above) and `EXTENDED_MANIFEST` (additional pcaps,
added alongside, not overwriting). Both are merged into `ALL_MANIFEST`, which is used by the
download/Maltrail/Zeek/summary loops of sections B–E — so simply run the notebook as usual; there is no
extra step on the code side.

Current new entry: **IoT-23 scenario 1** (`CTU-IoT-Malware-Capture-1-1`, Stratosphere/Aposemat lab — the
same lab as our Dridex source), pcap ~139 MB. **[MEDIUM CONFIDENCE]** — size and URL verified through the
directory listing, NOT through an actual byte-exact download (unlike the 5 original pilot entries, which
are HIGH CONFIDENCE). The exact malware family name has not yet been read from that scenario's
`README.md` — read it before writing it in the paper.

**Why this has to be downloaded manually, not automatically by the notebook**: the domain
`mcfp.felk.cvut.cz` (host of IoT-23 and CTU-13) was blocked by the network allowlist of the development
sandbox in which the notebook was written — if the download cell (section B) shows
`[FAILED] ... ProxyError ... 403 Forbidden` for the `iot23_capture1` or `dridex` entries, that is not a
notebook bug but a limitation of the environment where the notebook was written. Solution: download it
manually on your own machine (the authors' Mac was shown to reach this domain since Dridex), place the
file exactly at `data/pcap_raw/iot23_capture1.pcap`, then re-run section B — the `[ALREADY PRESENT]`
branch will use it automatically without re-downloading.

Manual download URL:
```
https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/2018-05-09-192.168.100.103.pcap
-> save as data/pcap_raw/iot23_capture1.pcap
```

**CTU-13 is not yet implemented in code** — its structure is different (one 1.9 GB bundle containing 13
scenarios; each scenario has a full pcap of only the botnet portion + Argus-labelled NetFlow for all the
mixed Normal+Botnet+Background traffic). It is groundwork for a coherent population for Layer 2 (not just
a Layer 1 extension), so it is deliberately documented first in section F of the notebook (a note, not
running code) before being implemented — waiting for confirmation of the direction once it is clear which
scenarios to use. Bundle URL: `https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2`
(CC-BY 2.0 license).

**Verification before delivery (first batch, 25 August)**: the manifest change above was tested with
`jupyter nbconvert --execute` in the development sandbox — the 5 original pilot pcaps still downloaded
byte-exact, and the IoT-23 entry failed with a clear `[FAILED]` message. **What was NOT tested at
that point, and turned out to be the problem**: the REAL Maltrail/Zeek path against the IoT-23 pcap,
because Zeek was not installed in the sandbox — the cells processing it were always skipped there, so that
code had never actually been executed before it was run on the authors' Mac.

## Bug found in the real run (second batch, 25 August 2026) — FIXED

`iot23_capture1.pcap` was downloaded manually (145,928,231 bytes) and the notebook was run — the result
actually PROVED two good things before the notebook crashed:

- **Maltrail successfully detected IoT-23 traffic**: `returncode=0`, 3 alert lines, 2 unique observables,
  a `mirai`-class label (the exact content should be checked in `iot23_capture1.log`) — evidence that
  Layer 1 can be extended to IoT malware families, not only banking trojans.
- **Zeek also succeeded**: `returncode=0`, `conn.log` created normally.

The notebook then **crashed** (`StopIteration`) in section D.2, while building the combined table — a bug
purely in the notebook code, not in the data or the IoT-23 pcap. The line
`ground_truth = next(e.ground_truth for e in PILOT_MANIFEST if e.key == key)` only searched
`PILOT_MANIFEST` (the 5 original pcaps), while `iot23_capture1` exists only in `EXTENDED_MANIFEST` — as soon
as the loop reached it, the lookup failed completely and the notebook stopped before producing the summary
table. **Why this was not caught before delivery**: the development sandbox had no Zeek installed, so the
cell containing this bug was always skipped during testing — testing only reached the point the sandbox
could reach, not the whole real flow. Fixed (changed to `ALL_MANIFEST`) and, this time, re-verified by
running that cell's logic directly against a 6-pcap scenario (including `iot23_capture1`) outside the
notebook, so the same blind spot does not recur.

One other small issue spotted in the log was fixed at the same time: `iot23_capture1.log` has 1 line that
does not match the Maltrail parser regex (`[!] 1 line(s) DO NOT MATCH the regex`) — previously that line was only stored silently in the `_raw_line` column and never printed,
because it was cut off by `head(10)`. Now the content of lines that fail to match is printed directly, so
you can see which format the parser does not handle yet without digging manually.

**Re-run the notebook from the start** (the file in this folder has been updated) — the IoT-23 download is
reused through `[ALREADY PRESENT]`; no need to download it again.

## Second run (after the fix above) — COMPLETE, plus two new findings (25 August 2026)

The fixed notebook was re-run — this time **the section E summary table was produced in full**, with no
crash:

| pcap | Maltrail alerts | Zeek flow rows |
|---|---|---|
| zeus | 18 | 22,053 |
| tinba | 1002 | 10,813 |
| dridex | 0 | 9,384 |
| bittorrent | 0 | 7,517 |
| skype | 0 | 6,321 |
| iot23_capture1 | 3 | **1,008,748** |

Two new things emerged from this run:

1. **The Zeus alert count keeps changing** (16 → 13 → 13 → 18 → 16 → 17 → 18), although the pcap is
   byte-identical in every run. The root cause was narrowed down & Fix #2 (the `header.getts()` patch) was
   implemented, BUT not yet sufficiently confirmed — see "Investigation of the Zeus alert-count drift"
   below. **Do not quote a single Zeus alert count in the paper until section C.5 (N=5 runs) is IDENTICAL.**
2. **`iot23_capture1` produces 1,008,748 Zeek flow rows** — two orders of magnitude more than any other
   pcap (range 6,321–22,053). [MEDIUM CONFIDENCE, NOT verified] consistent with a Mirai-class botnet
   scanning pattern (host `192.168.100.103` contacts a very large number of different external
   destinations, including a Tor exit node — see the regex section below). If used in a combined/pooled
   analysis later, this pcap will dominate the flow rows disproportionately — it needs handling (e.g.
   sampling, or analysing it separately) before being combined with the other 5 pcaps.

## Investigation of the Zeus alert-count drift (25 August 2026) — root cause found

Sequence of 4 runs on the byte-identical `zeus.pcap`: 16 → 13 → 13 → 18. The pattern goes up and down, not
monotonically — which by itself already refutes the initial guess "trails.csv was stale, refetched once,
then stable".

**Root cause, read directly from the code of `tools/maltrail/old/sensor.py` + `core/alert.py` +
`maltrail.local.conf`** [HIGH CONFIDENCE — not a guess, shown from the code]:

- `ALERT_THROTTLE 300` in `core/alert.py` is **NOT** the cause — it was suspected, but that function damps
  OUTGOING notifications (Slack/webhook) that read the log file ALREADY written; it does not control what
  goes into `zeus.log` itself.
- The real cause: the capture callback in `old/sensor.py` replaces the original pcap timestamp with the
  **process wall clock** (`time.time()`) — the official workaround for a pcapy-ng bug on Python 3 (the
  tool author's own comment: *"pcapy-ng returns unusable header timestamps on Python 3, so the wall clock
  is substituted"*). As a result ALL time-windowed heuristics (burst dedup, DNS exhaustion, scan window)
  also use the wall clock rather than the pcap's own time — so the results depend on the replay speed at
  that moment, which can differ per run.
- Made worse by `PROCESS_COUNT 16` (16 parallel processes) without `USE_CAPTURE_AFFINITY` — the ORIGINAL
  comments in `maltrail.local.conf` itself already document exactly this failure pattern: a round-robin
  worker pool splits the state of one source IP across many processes, so detection needs a signal ~
  PROCESS_COUNT times larger to trigger, or records duplicate events per worker.
- Supporting evidence: the `(static)` heuristics (per-packet lookup, no cross-time state) are **stable**
  across all runs — Tinba stays at 1002 in 4 runs. The `(heuristic)` ones (needing state/time windows) are
  the ones that drift — exactly 2 of the last 18 Zeus lines.

**Fix #1 implemented (25 August 2026)**: `build_maltrail_local_conf()` in section C.2 replaces
`PROCESS_COUNT 16` (the upstream template default) with `PROCESS_COUNT 1` whenever `maltrail.local.conf` is
regenerated. Tested with a fixture before delivery; the result is always exactly one `PROCESS_COUNT 1` line.

**AUDIT of the actual results (25 August 2026) — Fix #1 PROVEN INSUFFICIENT**: section C.5 (first 2x runs)
was run, and the results **DIFFERED (17 vs 18 lines)** — and within the same notebook execution, sections
C.3/C.4 (same `PROCESS_COUNT 1` config) produced **16**. So three different numbers (16/17/18) from a
byte-identical `zeus.pcap`, identical config, in one notebook run. This refutes the idea that
`PROCESS_COUNT 16` is the dominant factor — the variance with `PROCESS_COUNT 1` does not look smaller than
before (16→13→13→18).

**Further investigation (25 August 2026) — root cause narrowed, Fix #2 added**: `old/sensor.py` was re-read
down to the execution path that is actually active for our configuration (`PROCESS_COUNT 1`,
`USE_FAST_PREFILTER` off — confirmed empty in the `maltrail.local.conf` in use). With `PROCESS_COUNT 1`, the
packet processing order is 100% deterministic (one capture thread, reading `pcap.next()` sequentially from
the file) — BUT the wall-clock value (`time.time()`) attached to each packet is STILL non-deterministic,
because it depends on the real execution speed (I/O, CPU load, OS scheduling), which differs per run. The
time-windowed heuristics make decisions based on the *delta* between those timestamps, so their results
change even when the packet order is exactly the same. This explains why `PROCESS_COUNT 1` alone is not
enough [now HIGH CONFIDENCE — traced down to the code path that actually runs, not a guess].

The claim in the code's own comment (*"pcapy-ng returns unusable header timestamps on Python 3"*) was
**re-tested empirically** — a synthetic 5-packet pcap with known microsecond-precision timestamps was
created and read back with `pcapy.open_offline()` + `header.getts()` (the same library used by
`sensor.py`). Result: `header.getts()` returns the original timestamp CORRECTLY, matching down to the
microsecond, with `pcapy-ng` 2.1.0 on Python 3.11. The "unusable" claim probably comes from an older
`pcapy-ng` version (the library is maintained by Maltrail's own author and has gained features since that
workaround was written) — the workaround itself was never removed from `old/sensor.py`, which is already
legacy/not actively developed.

**Fix #2**: a new cell, **section C.1b**, adds (a) a self-test running exactly the same test through this
folder's own `.venv` — so we KNOW, rather than assume, whether `getts()` is valid on the Python
3.9.6/`pcapy-ng` version actually used; and (b) a patch to `old/sensor.py` that switches the source of
`sec`/`usec` to `header.getts()` ONLY for offline mode (`--offline`, all our experiments), with an automatic
fallback + a one-time warning to the wall clock if it turns out to be invalid in that environment — so the
patch is safe even if the self-test fails (behaviour is the same as before patching, no added risk). Live
capture (outside the scope of this research) is not touched at all. Idempotent.

Tested before delivery: the patch was applied to an upstream `tools/maltrail` clone (confirmed byte-identical
to the one on the authors' Mac by direct comparison), `py_compile` passes, 4 logic scenarios (valid/garbage/
future timestamps, live-capture mode) all pass isolated tests, and idempotency is verified. **Not yet
verified running in full inside the real `sensor.py`** (the development sandbox did not have a complete
Maltrail with trail feeds) — which is why section C.5 (now N=5 runs, not 2) must still be re-run.

**Empirical verification, section C.5 (updated, now N=5 runs)** — run Maltrail 5x in a row on `zeus.pcap`
with the same trail snapshot, report all the numbers + an IDENTICAL/DIFFERENT verdict. Tested with fixtures
(all equal, still different, 1 outlier out of 5) before delivery. **This is what needs to be run** (order:
C.1b then C.2 then C.3 then C.5) as the final proof of whether the combination of both fixes is enough.

**Implications for the paper**: the number of Maltrail alerts for the same pcap is NOT fully reproducible
with the default configuration (`PROCESS_COUNT 16` + wall-clock substitution) — worth stating explicitly in
the methodology/limitations section. If Fix #1+#2 prove sufficient (C.5 = IDENTICAL over 5 runs), also
mention them as a verified mitigation, including N runs & their dates.

## Further investigation — zeus/iot23 alerts collapsing to 0 (26 August 2026)

After Fix #1+#2 above, a new and more serious finding than mere count drift appeared: some C.3/C.5 runs
produced **0 alerts** for `zeus.pcap` (down from 16–18) and **0 alerts** for `iot23_capture1.pcap` (down
from 3), while other pcaps (including Tinba, `(static)` heuristics) stayed stable. This is no longer small
drift — it is a total collapse on two specific pcaps.

**Initial hypothesis proposed (and already REFUTED empirically)**: `trails.csv` (Maltrail's local
blacklist feed, normally refreshed every `UPDATE_PERIOD` of 24 hours) changed content between the test
sessions of 25 August, so some entries that used to match zeus/iot23 disappeared.

**Direct check** [HIGH CONFIDENCE — direct file-timestamp evidence from the authors' Mac, not a guess]: the
`~/.maltrail/` folder was checked directly. All related files (`trails.csv`, `trails.csv.bin`,
`trails.csv.confidence`, `ipcat.csv`, `ipcat.sqlite`) have mtimes clustered at **24 August 2026 ~14:43
UTC** — and that mtime **DID NOT CHANGE** throughout all the 25 August test sessions (both the runs
producing 16-18 alerts and the runs that collapsed to 0 used exactly the same files, byte-identical
according to filesystem timestamps). `trails.csv` was also "stale" relative to `UPDATE_PERIOD` 24 hours
(about 34 hours old when checked) — but stale does not mean its content differed between test sessions,
and it was shown not to.

**Conclusion: the trails.csv content-drift hypothesis is withdrawn — PROVEN FALSE.** The blacklist content
used was identical in all sessions of 25 August. The cause of the alert collapse is not here.

**Mitigation still applied**: the current `trails.csv` + `trails.csv.confidence` snapshot was frozen
(copied with the original mtime preserved) into the `trails_snapshots/` folder of this project, as a fixed
reference for the experiments — so that in future, even if Maltrail refreshes its feeds again, we have a
copy that is guaranteed not to change, for reproduction. A manifest file
(`MANIFEST_trails_2026-08-24T1443Z.txt`) records the freeze time, source path, size and SHA-256 hash.

**New hypothesis, NOT YET TESTED EMPIRICALLY** [LOW-MEDIUM CONFIDENCE — read from the code only, not
tested; per this project's own lesson, claims based only on reading code MUST NOT be trusted until verified
by a real run]: the burst-skip dedup logic in `old/sensor.py` (global variable `_last_syn`, comparing the
tuple `(sec, src_ip, src_port, dst_ip, dst_port)` between consecutive SYN packets — if identical, the packet
is `return`ed BEFORE it is ever checked against the blacklist). Fix #2 (section above) switches the source
of `sec`/`usec` from the wall clock to the original pcap timestamp ONLY in offline mode. The original
timestamps of an old botnet capture can be much denser (many SYN packets within the same integer second)
than the wall clock used before (whose speed depends on the replay process) — if so, the burst-skip filter
may now catch (skip) far more SYN packets than before, including packets that should match the blacklist.
This is only a guess from reading the code — **no real-run evidence confirms it yet**.

**Diagnostic instrumentation added (section C.1c, notebook)**: instead of guessing further from the code, a
pure counter patch (it does not change detection behaviour at all) was added to `old/sensor.py`, recording
at each stage of the SYN pipeline: `total` (all SYN packets seen), `burst_skipped` (skipped by burst dedup
before being checked against the blacklist), `trail_hit` (matches the blacklist, either branch),
`logged_skipped` (matches but damped by the secondary dedup `_last_logged_syn`), `alert_emitted` (actually
recorded as an alert). Printed once per pcap at the end of offline mode, in the format `[diag] SYN counters
for '<pcap>': total=... burst_skipped=... trail_hit=... logged_skipped=... alert_emitted=...`. Sections C.3
and C.5 were also modified so these `[diag]` lines are displayed (previously the subprocess stdout was
captured but not printed unless it failed).

**How to read the results**: if the burst-skip hypothesis is right, `burst_skipped` for zeus/iot23 will be
proportionally much higher than for Tinba (stable `(static)`, which does not go through this path at all
because it is not a SYN-window heuristic). If `trail_hit` is already 0 from the start, the problem is not
burst-skip but the blacklist matching itself (another possibility, not yet investigated). If `trail_hit` >
0 but `alert_emitted` = 0, the problem lies in additional filter conditions (`"attacker"` / `"malware"` /
`"parking site"` in the trail line) — yet another possibility.

**Not yet verified in a real run** — this patch was only tested in isolation: `py_compile` passes,
idempotency verified, and confirmed not to conflict with the Fix #2 patch (it touches different lines). It
needs to be re-run C.1b → C.2 → C.1c → C.3 → C.5 against `zeus.pcap`, `iot23_capture1.pcap` and
`tinba.pcap` (as a control, `burst_skipped` should be low/zero), and the `[diag]` numbers reported back as
the final proof.

**Implications for the paper**: until this investigation is complete, NO Layer 1 alert count from
`zeus.pcap` or `iot23_capture1.pcap` may be quoted — the status is still "root cause not found", not merely
"small drift mitigated".

### Real-run results of C.1c (26 August 2026) — the burst-skip hypothesis REFUTED as well, a new gap found

The C.1c instrumentation was run on the authors' Mac. `[diag]` results [HIGH CONFIDENCE — numbers taken
directly from the real run]:

| pcap | total SYN | burst_skipped | trail_hit | logged_skipped | alert_emitted |
|---|---|---|---|---|---|
| zeus | 32,011 | 18,140 (56.7%) | **0** | 0 | 0 |
| tinba | 0 | 0 | 0 | 0 | 0 |
| dridex | 4,170 | 1,074 (25.8%) | 0 | 0 | 0 |
| bittorrent | 0 | 0 | 0 | 0 | 0 |
| skype | 0 | 0 | 0 | 0 | 0 |
| iot23_capture1 | 964,942 | 400 (0.04%) | 5 | 0 | 5 |

**The burst-skip hypothesis (above) is REFUTED in its simple form, for Zeus** [HIGH CONFIDENCE — these are
numbers, not interpretation]: if burst-skip were masking real matches, the pattern should be `trail_hit > 0`
but masked at a later stage. What happened: of the 13,871 Zeus SYN packets that PASSED burst-skip and were
actually checked against the blacklist, **not a single one** matched (`trail_hit=0`). So the problem is not
"a match masked by burst-skip" — the match itself never happens in the instrumented code block. For IoT-23,
by contrast, the numbers are consistent with history (5 alerts, `trail_hit=5`, `burst_skipped` only 0.04%)
— so the instrumentation itself is proven correct, not a bug in the patch. Tinba/BitTorrent/Skype: `total=0`
— makes sense, because Tinba is detected through DGA domains (the DNS path, not SYN). **Correction of
17 October 2026 (found during the Layer 2 investigation, verified directly through `conn.log`):** the reason
for BitTorrent/Skype is NOT that they are "dominated by UDP" as written earlier — both are 100% TCP (7,517
and 6,321 `conn.log` rows, zero UDP). The real reason: both pcaps are synthetic traffic from an IXIA
BreakingPoint-style traffic generator (test-tool MAC prefix, uniform flows between two fixed address ranges
without real handshakes) — there is no DNS, HTTP or any real indicator that any Maltrail detection path
(SYN or non-SYN) could match, not because UDP is not instrumented. See `layer2-behavior-features/README.md`
for full details.

**A design gap found while re-reading `old/sensor.py`, acknowledged openly**: the C.1c instrumentation only
observes the `if flags == 2` (SYN) block. But `_process_packet` also checks `trails` in many other places
that are not instrumented at all — the TCP port-scan heuristic, the HTTP checks (sinkhole response,
suspicious user agent, suspicious URL/domain), and the UDP/DNS path — all independent of the SYN block and
all using the `sec`/`usec` changed by Fix #2. Our own earlier note on Zeus ("ALERT — 'blackshades (malware)'
**+ several heuristics**") is consistent with part of the old alerts coming from these other paths, not only
from the SYN block.

### Instrumentation v2 (section C.1d, notebook, 26 August 2026) — pre-burst-skip membership test + per-path log_event breakdown

Two things were added, addressing the two gaps above:

1. **A trail-membership test BEFORE the burst-skip return** — EXACTLY the same matching predicate as the
   original code (bare IP `dst_ip in trails`/`src_ip in trails` OR the combined form `addr_port(ip, port)`,
   i.e. `"IP:port"` — also the literal key form used in `trails.csv`, which answers the suggestion about
   src+port combinations) evaluated BEFORE the line `if _ == _last_syn: return`. New counters:
   `would_match_total`, `would_match_dst`, `would_match_src`, `would_match_via_addr_port` (matches that only
   arise through the IP+port combination), `burst_skipped_would_have_matched`. This is the DEFINITIVE test
   of the burst-skip hypothesis: if `would_match_total` for zeus stays 0, burst-skip is not the cause at all
   (the problem is elsewhere); if `would_match_total > 0` while `trail_hit` (v1) stays 0, burst-skip is
   PROVEN to swallow matches that should exist.
2. **A breakdown of `log_event` calls per `TRAIL.*` type** — `log_event()` (the one function that ALL
   trail-matching paths go through, not just SYN) is wrapped to count how many times the types
   `IP`/`IPORT`/`DNS`/`HTTP`/`URL`/`UA`/`PORT` are actually called per pcap in offline mode. Printed as
   `[diag-v2] log_event calls for '<pcap>': <type>=<n>, ...`. **Important note**: a recorded call does NOT
   guarantee that a line is written to `<pcap>.log` — `log_event()` itself has internal
   whitelist/`IGNORE_EVENTS`/per-second dedup gates (`current_bucket = sec // PROCESS_COUNT`, found while
   tracing `core/log.py`) that this patch does not touch — so there may still be a gap between "called" and
   "written to the log".

**On the suggestion (features from the 14 IPv4 header fields, aggregated combinations such as src+port)** —
considered, partly used (point 1 above directly addresses the IP+port combination), partly deliberately NOT
used: the ~10 other IPv4 header fields besides IP/port (TTL, ToS, packet ID, fragmentation flags & offset,
checksum, IHL, total length) are not used anywhere by Maltrail's existing blacklist/heuristic matching
logic, so adding them to this Layer 1 bug diagnostic would not help — it is a valid idea for another
direction (header/packet-based Layer 2 features, in line with the "3 granularities" idea of an older
doctoral draft), not for this bug. Deliberately left out to keep the patch scope focused and clearly
testable.

Tested before delivery: the `would_match_*` predicate was verified through 7 isolated logic scenarios
(bare-IP match, addr_port-only match, no match, localhost exclusion, dst+src both matching — all as
expected); the `log_event` wrapper was tested for offline-mode counting per type, zero overhead/zero risk in
live mode, and short/broken tuples not causing crashes. Applied on top of a clone already patched with
Fix #2 + C.1c (v1) — confirmed not to conflict (the diff touches only 4 places), `py_compile` passes,
idempotency verified.

**Bug found in the real run (26 August 2026, within a few hours) — FIXED**: the first run of section C.1d
**crashed** with `FileNotFoundError` inside the block `if __name__ == "__main__": ... Path(sys.argv[1])`.
The root cause was purely an authoring mistake: when embedding the patch module into the notebook cell, the
CONTENT OF THE FILE `diag_patcher_v2.py` was pasted AS IS, including the `if __name__ == "__main__":` epilogue
originally intended only for command-line use (`python diag_patcher_v2.py <path>`). The problem: inside a
Jupyter cell, `__name__` IS equal to `"__main__"` — so that block ran too, tried `Path(sys.argv[1])`, and
`sys.argv[1]` in the Jupyter kernel turned out not to be a sensor.py argument at all but the path of the
kernel connection file (`--f=/Users/.../kernel-....json`) — `.read_text()` on that path obviously fails.
This is not a problem in the `patch_sensor_diagnostic_v2()` code itself (the core function is untouched) —
purely a CLI epilogue that should not have been embedded. The earlier C.1c (v1) cell was SAFE from the same
bug because it happened to be assembled manually without that epilogue; this C.1d cell was assembled by
copying the whole file and the epilogue was missed — an oversight that should have been caught before
delivery. **Impact**: because the exception stopped the cell BEFORE the line
`print(patch_sensor_diagnostic_v2(SENSOR_PY))` could run, `old/sensor.py` was NEVER actually patched with
v2 in that run — so there is no `[diag-v2]` data to analyse from that run.

Fix: the `if __name__ == "__main__":` epilogue was removed from the notebook cell (the
`patch_sensor_diagnostic_v2()` function itself was not changed at all). Verified by simulating exactly the
failing scenario (`__name__="__main__"` + `sys.argv` filled with a fake kernel connection path) through
`exec()` of the fixed cell content — it now runs cleanly with no exception. The whole notebook (36 cells)
was re-validated and `py_compile` passes.

**Not yet verified in a real run** — section C.1d needs to be RE-RUN on the Mac with this fixed notebook
(order: C.1b → C.2 → C.1c → C.1d → C.3 → C.5), and all `[diag-v2]` numbers reported back.

### Instrumentation v3 (section C.1e, notebook, 26 August 2026) — getting through the 4 internal gates of `log_event()`

The `[diag-v2]` results (C.1d) gave an important number: `log_event()` IS CALLED 5,818 times for zeus.pcap
(`DNS=5554, UA=6, URL=258`), not zero — so the "no match at all" hypothesis (C.1c/v1) is also refuted. But
`zeus.log` still has 0 lines. The bottleneck has definitely moved INSIDE `log_event()` itself
(`core/log.py`), no longer the trail matching in `sensor.py`. **[HIGH CONFIDENCE]** — directly from the
`[diag-v2]` numbers of the real run.

`core/log.py` (461 lines, read in full) has 4 successive gates that can drop an event before it is written:
(1) `ignore_event()` — purely config-based, time-independent; (2) the whitelist gate —
`check_whitelisted(src_ip/dst_ip)`, EXCEPT for `DNS`-type trails (explicitly excluded in the original code;
its own comment says DNS cannot be whitelisted by IP) — directly relevant because 5,554/5,818 of the zeus
calls are of type DNS; (3) the "condense" queue — if `info` contains one of `CONDENSE_ON_INFO_KEYWORDS =
("attacker", "reputation", "scanner", "user agent", "tor exit", "port scanning", "potential infection")`,
the event is queued per `(src_ip, trail)` and only written later by the background thread
`flush_condensed_events` — exactly matching the `UA=6` label ("user agent (suspicious)"); (4) the per-second
throttle — `current_bucket = sec // config.PROCESS_COUNT`, which depends DIRECTLY on `sec`, the value Fix #2
changed from the wall clock to the original pcap timestamp.

The v3 patch has two parts in two files: `patch_log_diagnostic_gates()` targets `core/log.py` directly (the
first time this file is touched in this experiment), adding 6 counters (`total, dropped_ignore_event,
dropped_whitelisted, dropped_skip_write, queued_condense, dropped_throttle, written`);
`patch_sensor_diagnostic_v3()` targets `old/sensor.py`, imports the `core.log` module (`from core import log
as _diag_log_module`, NOT `from core.log import _DIAG_LOG_GATE_COUNTERS` directly — so the reference keeps
pointing to the same dict mutated in place, without manual syncing) and then prints a `[diag-v3]` line at the
same EOF point as `[diag]`/`[diag-v2]`.

**Ordering prerequisite (deliberately designed to fail fast)**: `core/log.py` MUST be patched before
`old/sensor.py` is imported/run — if the order is reversed, `sensor.py` fails with a CLEAR `AttributeError`
(rather than silently miscounting), because `_diag_log_module._DIAG_LOG_GATE_COUNTERS` does not exist yet.
The C.1e notebook cell runs both parts in the right order automatically.

**An unexpected finding from the testing process itself** (an ORIGINAL property of Maltrail, not a bug in
the patch — it only became apparent after the first test FAILED): the per-second throttle gate turns out to
be looser than first assumed. The original code resets the dedup set `_thread_data.log_trails` to empty when
entering a new second bucket, but does NOT immediately put the bucket's first event into the set — only the
second event onwards is checked/added. As a result the 1st and 2nd events with identical `(ip, trail)` in
the same second ALWAYS pass; only the 3rd event is actually hit by `dropped_throttle`. The scenario test
initially used 2 events and failed (assert error) — it was corrected to 3 events after seeing that failure,
not guessed from the start. **[HIGH CONFIDENCE]** for this behaviour — verified by executing the original
function directly (not just reading the code). Important for later interpretation: `dropped_throttle` only
increases when there are >=3 identical `(ip, trail)` events within the same second, not 2.

Tested before delivery: (a) `patch_log_diagnostic_gates` — idempotency (patched → already patched),
`py_compile` passes, a clean diff of exactly 5 places, the failure path (`FAILED-block-not-found`) tested by deliberately breaking one anchor and confirming that NO file is written
at all; (b) 8 isolated behaviour scenarios calling `log_event()` directly with mocked dependencies — one
scenario per gate, the DNS exception in the whitelist, live mode (`config.pcap_file` empty) confirmed to
count nothing, short tuples confirmed NOT to change the original exception behaviour (`ValueError` still
propagates); (c) `patch_sensor_diagnostic_v3` — idempotency, the v2 prerequisite checked explicitly
(`FAILED-v2-prerequisite-missing` when tested without v2), a clean diff
of 2 places, `py_compile` passes for the combined Fix#2+v1+v2+v3; (d) **a real bug found & fixed BEFORE the
cell was finalised**: both patchers (log & sensor) define the module-level names `_MARKER` and `_ALL_PAIRS` —
merged as they are into one notebook cell (one shared execution namespace), the second definition would
OVERWRITE the first, making `patch_log_diagnostic_gates()` read the sensor patch's marker/block pairs when
called. Fixed by renaming the sensor patch's variables for the combined version in this cell (`_MARKER` →
`_MARKER_V3_SENSOR`, `_ALL_PAIRS` → `_ALL_PAIRS_V3_SENSOR`), then re-tested through an `exec()` simulating
exactly the cell content twice in a row (patched/patched, then already-patched/already-patched) before it
was considered safe to deliver. The root cause was purely carelessness in merging two independent modules
into one namespace without checking for name collisions first — found through testing, not manual code
review.

**Not yet verified in a real run** — it needs to be run on the Mac (order: C.1b → C.2 → C.1c → C.1d → C.1e →
C.3 → C.5), and all `[diag-v3]` numbers reported back.

## Parser regex fixed — "tor exit node" format (25 August 2026)

The line that failed the regex in `iot23_capture1.log` (mentioned above) turned out to be a new, valid
format, not a broken line:

```
"2026-08-25 15:33:46.028537" MacBook-Pro-Arief.local 192.168.100.103 56801 192.42.116.42 17901 TCP IP 192.42.116.42 "tor exit node (suspicious)" "torproject.org (+abuseipdb.com,dataplane.org,sblam.com)"
```

The difference from the usual format: the `trail_category` at the end of the line is usually bare
parentheses (`(static)`, `(heuristic)`), but here it is **quoted** and its content is a multi-source citation
from the "tor exit node" feed (`torproject.org (+abuseipdb.com,dataplane.org,sblam.com)`) — whose content
itself contains parentheses & commas. The `MALTRAIL_LOG_RE` regex in section C.4 now accepts BOTH forms
(bare parentheses OR quoted), merged into the same single `trail_category` column as before — no change to
other columns or to code using `all_maltrail`.

Tested with a 4-case fixture before delivery: a regular `(static)` line, a `(heuristic)` line with a space
before the parenthesis, a line with a quoted observable (User-Agent), and the real "tor exit node" line from
the actual log — all four match and yield the right `trail_category`. Lines that really are broken (matching
no pattern) are still caught as "NO MATCH" as before; no regression on that path.

## Log-file discovery bug v3 — the real cause of the Zeus "alert collapse", NOT a detection failure (26 August 2026)

**This is the turning point of the investigation.** The C.1e instrumentation (see the section above) yields
`written=5696` for `zeus.pcap` — passing ALL 4 internal gates of `log_event()`. But section C.4 still
reports `[zeus] alert lines=0`. Cross-check: `tinba` in the same run shows `written=1002` AND
`alert lines=1002` — an exact match — so the `written` counter is PROVEN valid, and the zeus contradiction
(many vs zero) is real, not a misreading of the instrumentation.

**Root cause, traced to `core/log.py` lines 54-58** (`get_event_log_handle(sec)`):
```python
localtime = time.localtime(sec)
_ = os.path.join(config.LOG_DIR, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))
```
Maltrail writes to a file named after **the date of `sec`** — not `<pcap_name>.log`. Since the
offline-timestamp patch (section C.1b), `sec` in offline mode = the ORIGINAL pcap timestamp, not the wall
clock. The old C.3/C.5 driver (`maltrail_dated_log_path()`) only looked for `datetime.date.today()` — TODAY's
date. Pcaps whose original timestamp is not today were written to a file the driver never looked for.

**Verified through 3 independent sources, not just by reading the code:**
1. Direct extraction of pcap bytes: the first packet of `zeus.pcap` = **2012-05-29**. `tinba.pcap` =
   near-epoch (broken/relative) timestamps that FAIL the sanity check of the offline-timestamp patch
   (`631152000 <= ts <= now`) and automatically fall back to the wall clock — which is why tinba "happened"
   to match today's date and never looked problematic.
2. Direct check of `data/maltrail_out/` on the Mac: there is a `2012-05-29.log` — **205,092 lines**,
   29.9 MB, containing: 187,920 `blackshades (malware)` (DNS to `zxczxczxc.zapto.org`), 8,928
   `dynamic domain`, 7,884 `web shells`, 144 `ipinfo`, 108 `pua`, 72 `direct .exe download`, 36
   `user agent` — **exactly the SAME 7 categories** as the old `zeus.log` (from the 25 August run, before the
   offline-timestamp patch, when the wall clock happened to still be used). There are also `2018-05-12.log`
   and `2018-05-14.log` — belonging to `iot23_capture1.pcap` (labels "mass scanner"/"tor exit node",
   consistent with the history "5 alerts, trail_hit=5").
3. The file `2012-05-29.log` is an APPEND file accumulated over MANY runs during the 2 days of this
   investigation (not the output of one clean run) — so those 205,092 lines are a mixed representation, not
   a single-run metric that can be quoted directly.

**[HIGH CONFIDENCE]** — Maltrail's detection itself was never broken; its alerts were always there,
complete and diverse (7 categories). What was broken was purely the "which log file to look in" logic in our
own notebook code (sections C.3/C.5), which only became visible after the offline-timestamp patch made `sec`
realistic. All the C.1c (burst-skip) and C.1d/C.1e (internal `log_event` gates) work was NOT wasted — that
elimination process produced `written=5696`, the key evidence that led here.

**Impact on earlier conclusions — WITHDRAWN**: the C.5 run (determinism verification) before this fix
reported `All runs: [0, 0, 0, 0, 0]` → *"RESULT: IDENTICAL ... PROVEN SUFFICIENT, safe to lock as this
experiment's fixed configuration — mention in the paper's methodology."* **That conclusion
was WRONG and is withdrawn** — `0=0=0=0=0` is literally identical, but because all five runs failed to find
the same file, not because the pipeline is genuinely reproducible. The determinism claim for PROCESS_COUNT 1
+ the offline-timestamp patch must NOT be considered verified until C.5 is re-run with this fix.

**Fix**: `maltrail_dated_log_path()` was removed and replaced by `snapshot_dated_logs()` +
`collect_new_log_lines()` — snapshot the byte size of every `<YYYY-MM-DD>.log` file in `MALTRAIL_OUT_DIR`
BEFORE the subprocess runs, then afterwards take EXACTLY the bytes that were added (`byte[size_before:]`) from
whichever file was touched — instead of guessing the file name from any date (today OR from `sec`). This is
automatically correct for ALL cases: new files, old files that have accumulated (exactly the zeus case), two
files touched at once (a pcap crossing midnight / two pcaps with the same wall-clock fallback), and files
that shrank since the snapshot (taken in full, not ignored) — so there is no need to delete/clean old
accumulated files for the mechanism to stay correct in future. Applied in TWO places: section C.3 (the main
per-pcap loop) and section C.5 (the determinism loop; both use the same function, defined once in C.3).

Tested before delivery: 9 isolated scenarios of the `snapshot_dated_logs`/`collect_new_log_lines` functions
with a real sandbox directory (not mocks) — directory not yet existing, new file created, old file appended
(the real zeus scenario), two files touched at once, no file touched (the dridex/bittorrent/skype case with
genuinely zero log_event calls), file shrunk since the snapshot, non-dated-log files (`error.log`,
`*.sqlite`) ignored, line counting via `count(b"\n")` consistent, and a reproduction of the real zeus
scenario (an old file of 50,000 lines + a delta of 5,696 new lines — only the new lines are included, the
old content does not get mixed in). The whole notebook (38 cells) was re-validated and `py_compile` passes
for every code cell.

**Not yet verified in a real run with the full pipeline** — it needs to be re-run (order: C.1b → C.2 → C.1c
→ C.1d → C.1e → **C.3 (fixed)** → C.4 → **C.5 (fixed)**), and the `alert lines` per pcap and the
C.5 determinism result reported back. Until then, **no Layer 1 alert count at all (zeus/iot23/dridex/tinba)
may be quoted in the manuscript** — no longer because they are suspected to be zero, but because the correct
numbers (not the result of looking in the wrong file) have never been measured in one clean run.

## Log-file fix confirmed working + tinba turns out to be non-deterministic (28 August 2026)

**The real run of 28 August confirms that the log-file fix above really works**:
```
[zeus] alert lines=5697, log=zeus.log (from: 2012-05-29.log)
[iot23_capture1] alert lines=5, log=iot23_capture1.log (from: 2018-05-10.log, 2018-05-11.log, 2018-05-12.log, 2018-05-14.log)
```
Zeus is now found (no longer 0), and `iot23_capture1` even touches **4 different dated files at once** (the
pcap spans several real days) — exactly the scenario tested in isolation earlier, merged correctly. C.5 was
re-run: `[5697, 5697, 5697, 5697, 5697]` — 5 identical runs, and this time identical because the same file
really was found every time (not because all five failed). **The zeus determinism claim is now VALID** and
may be quoted in the paper's methodology.

**Minor finding**: `[diag-v3] written=5696` vs the real line count `5697` — a difference of 1, consistent
over 6 observations (1 C.3 run + 5 C.5 runs, all exactly 5696 vs 5697). The most plausible explanation
**[HIGH CONFIDENCE, reproducible 6/6]**: the `[diag-v3]` line is printed exactly when the packet loop reaches
EOF, but the 6 UA events in the "condense" queue are only flushed by the background thread AFTER that print
point — the printed number slightly under-counts, while the file-discovery mechanism (byte delta, run after
the subprocess has really finished) captures the total correctly. The exact race point has not been
verified directly.

**A more serious finding — `tinba.pcap` is NOT deterministic**, found by comparing the runs of 26 vs
28 August:

| | 26 August | 28 August |
|---|---|---|
| total `log_event` calls | 10827 | 10827 (same) |
| `dropped_throttle` | 9825 | 8823 |
| `written` (alert lines) | 1002 | **2004** |

The number of `log_event` calls is identical (the matching itself is stable), but the final result differs
by almost 2x. **Root cause**: a raw byte extraction of `tinba.pcap` shows per-packet `ts_sec` of 0..~1755
(anchored near the 1970-01-01 epoch, not the real capture date — probably a synthetic/relative pcap). These
values FAIL the sanity-check floor of the Fix #2 offline-timestamp patch (`>= 631152000`, year 1990), so
they automatically fall back to the **real wall clock** — the per-second throttle (`sec // PROCESS_COUNT`)
then depends on the real replay speed on the machine, not on the pcap content. Unlike zeus: zeus has REAL
timestamps (2012-05-29) that passed the sanity check from the start, so it was already deterministic through
Fix #2 without any further fix.

**Fix (patch offline-timestamp-relative-fallback, complementing Fix #2, not replacing it)**: those
near-epoch timestamps are NOT garbage — they are read directly from the pcap file bytes, so they are always
EXACTLY the same every time the same file is read again (deterministic by construction). One branch was
added: if `ts_sec` is valid (0 ≤ ts_sec < floor, usec within range) but below the floor, shift it by a
**FIXED offset** (the sanity-check floor itself, `631152000`) — not `time.time()`. This is deterministic (a
constant offset) AND preserves the original inter-packet gaps (which determine the throttle result), unlike
the wall-clock fallback, which replaces all timing with the replay process's time. Real timestamps (zeus and
others, already passing the primary sanity check) are not touched at all by this new branch.

Tested before delivery: (a) the patch — idempotency (the FIRST attempt passed "patched" but FAILED "already
patched" because the marker string turned out not to be actually embedded in the new block's text — caught
by this test itself and fixed before continuing), `py_compile` passes, a clean diff of 1 place, the Fix #2
prerequisite checked explicitly, the failure path (anchor deliberately broken) confirmed NOT to write
anything; (b) 11 isolated logic scenarios — real timestamps untouched, near-epoch timestamps shifted
correctly (including `ts_sec=0` and `ts_sec=1755`, the bounds of the real tinba pcap), 20x calls with
identical input give identical output, the boundary exactly at the floor (not shifted twice), negative
`ts_sec`/broken `usec`/exceptions from `getts()` still fall back (not wrongly passed), live mode untouched;
(c) **direct confirmation with `pcapy` + the real `tinba.pcap`/`zeus.pcap`** (not just mocks) — 22,000 tinba
packets read, raw ts_sec range exactly 0..1755 (matching the manual extraction), the per-second throttle
buckets of two simulated "runs" with `now` (wall clock) ~11.5 days apart are **exactly identical** — direct
proof that this fix removes the root of the non-determinism; zeus.pcap (93,141 packets) confirmed to go 100%
through the old branch, not touched at all.

Section C.5 now checks **zeus AND tinba** automatically in one go (`DETERMINISM_CHECK_KEYS`, no longer a single
manual key as before).

**Not yet verified in a real run** — it needs to be run on the Mac (order: C.1b → **relative-timestamp fix
(new)** → C.2 → C.1c → C.1d → C.1e → C.3 → C.4 → **C.5 (checks zeus+tinba)**), and the tinba determinism
result reported back before its numbers may be quoted in the manuscript.

## Tinba relative-timestamp fix CONFIRMED in a real run + trails.csv pinning (28 August 2026)

**Real run (28 August, third `layer1_experiment.html` upload of the day)** — section C.5 confirms both pcaps
are DETERMINISTIC in a single execution:

```
zeus:  [5697, 5697, 5697, 5697, 5697]  -> DETERMINISTIC
tinba: [10902, 10902, 10902, 10902, 10902] -> DETERMINISTIC
```

[HIGH CONFIDENCE — numbers taken directly from the output of the uploaded run]. tinba is now read from
`1990-01-01.log`, exactly as designed (`631152000` = 1990-01-01, the sanity-check floor used as the offset).
The relative-timestamp fix (section above) is PROVEN to work in the real environment, not only in the
sandbox/with synthetic pcapy input.

**New finding — reproducibility ACROSS sessions, not within a session**: the total number of `log_event`
calls for tinba differs between the 01:55 run (before the fix, total=10827) and the 03:39 run (after the
fix, total=10902) — two SEPARATE runs on the same day, not repetitions within one C.5. Checked directly
[HIGH CONFIDENCE — mtime & live SHA-256 taken directly from `~/.maltrail/`]: `trails.csv` HAD in fact
changed since the frozen snapshot of 24 August (92,096,534 bytes) — the live mtime is now
`2026-08-28T01:52:20Z`, size 93,130,085 bytes. This does NOT contradict the conclusion "the trails.csv
drift hypothesis is PROVEN FALSE" above (24–25 August) — that conclusion is specific to the time window
tested then; now, >3 days later, `UPDATE_PERIOD` (24 hours) has had time to trigger a refresh.
[MEDIUM-HIGH CONFIDENCE, **minute-level precision not verified**] this is probably what explains the
10827 vs 10902 difference — but it is not established exactly which run used which trails.csv version;
**this needs verification** if the exact numbers are needed. iot23_capture1 (an old issue, total 8→14, still
open) did not change again today (still 14 in both 28 August runs) — so there is no new drift there related
to today's fix.

**Fix — section C.2a (notebook)**: `freeze_trails_snapshot()` freezes the LIVE `trails.csv` +
`trails.csv.confidence` into `trails_snapshots/` (manifest: mtime, size, SHA-256). `pin_trails_from_snapshot()`
restores that frozen snapshot BACK into `~/.maltrail/` before every experiment run, verifies the SHA-256
before AND after the restore, and deletes `trails.csv.bin`/`.bin.lock` (Maltrail's binary cache) so Maltrail
must rebuild from the freshly pinned trails.csv — if the old cache were left in place, the pinning could be
silently useless (the same class of bug as the earlier marker-not-embedded one).

**First pin baseline**: the current live trails.csv (mtime `2026-08-28T01:52:20Z`, SHA-256
`6b7d9e7b96af061ea7b4ece5e4da12959934e1c1f67d96816bac5171dc598740`) has been frozen into
`trails_snapshots/trails_2026-08-28T0152Z_frozen.csv[.confidence]` + `MANIFEST_trails_2026-08-28T0152Z.txt`
— chosen because it is most likely the same trails.csv used by the 03:39 run above (so the just-confirmed
5697/10902 numbers do not change again because of the pinning). `PINNED_TRAILS_STAMP` in cell C.2a locks to
this stamp explicitly (not an automatic "latest" pick) — a deliberate update, recorded here, if a new
baseline is ever needed.

Tested before delivery — 10 isolated scenarios (fixtures, not the real trails.csv): freeze fails cleanly if
`~/.maltrail` does not exist / the source files are incomplete; a successful freeze → manifest + byte-identical
copy (SHA-256 re-checked, not assumed); pin fails cleanly if the manifest does not exist; **a
freeze→drift→pin roundtrip** (live deliberately changed, pin restores it EXACTLY to the frozen content, old
`.bin` cache deleted); idempotency (pin 2x in a row, same final result); two fail-safe paths tested explicitly
— frozen snapshot missing from disk, and frozen snapshot CORRUPT (hash not matching the manifest) — both fail
cleanly WITHOUT touching the live trails.csv at all; `.bin`/`.bin.lock` not existing at all does not crash;
the manifest records the correct byte size; the manifest parser was also tested against the REAL manifest
text written by hand (including the extra narrative after the sha256 block). The FULL cell (exactly the
embedded text, not just a separate module) was re-executed end-to-end through `exec()`: manifest not yet
existing → `RuntimeError` (fail loudly, do not continue silently); then after a manual freeze + simulated
drift → the full cell pins successfully, live restored, old `.bin` deleted.

**Not yet verified in a real run** — it needs to be run on the Mac (section C.2a, after C.2, before C.3). If
it fails (`FAILED-...`), the cell raises an exception and STOPS execution — deliberately, so
that C.3/C.5 do not silently run with unpinned trail data. It is recommended to re-run C.3+C.5 once more
after C.2a is active, to confirm 5697/10902 stay exactly the same with the pin in place (closing the
verification loop — not just trusting the code, but looking at the numbers again).

## trails.csv pin bug found & fixed + CTU-Normal-32/33 run (22 October 2026)

**Context**: the manual section C recipe (outside the notebook, directly in a terminal) was run to scan
`ctu_normal32`/`ctu_normal33` (two benign captures; the pcaps were available but had never gone through the
real `sensor.py` — see the paper, §2.4/§3.5, for why this was a gap that needed closing). The first run
(`ctu_normal33`) finished with RC 0, but `trails.csv` **changed content DURING that run itself**: SHA-256
`6b7d9e7b96af061...` → `7cdabd0b...`, line count down from 1,791,806 to 1,632,628.

**Root cause** [HIGH CONFIDENCE, read directly from `core/update.py::update_trails`]:
`pin_trails_from_snapshot()` (section C.2a above, 28 August) uses `shutil.copy2()`, which **preserves the
mtime of the original snapshot file**, not the time it was pinned. The snapshot used is dated
`2026-08-28T0152Z` — so as of 22 October (>55 days later), this pin was already far beyond Maltrail's
`UPDATE_PERIOD` (24 hours) **counted from when the snapshot was made**, even though it was pinned only seconds
before the run. Maltrail silently rebuilt `trails.csv` from the static trails only (without feeds) right
after the pin "succeeded" — making the pinning useless without any sign of failure.

**This does NOT contradict the conclusion of the section "Further investigation — zeus/iot23 alerts collapsing
to 0" (26 August) above**, which withdrew the "trails.csv drift between sessions" hypothesis — that conclusion
is specific to a staleness of ~34 hours (the 25 August test sessions) and was proven correct for that range:
trails.csv really did not change within those 34 hours. Today's finding is the SAME mechanism (`UPDATE_PERIOD`
+ rebuild without feeds) but at a much more extreme staleness (55 days) that had never been tested before.
Both are consistent — not a contradiction; it simply was not found until now because there had never been a
real gap of >24 hours between a snapshot and its use.

**Is Table 5 (`pilot_summary_layer1.csv`, already in the paper) contaminated as well?**
[MEDIUM-HIGH CONFIDENCE] Most likely NOT. `pilot_summary_layer1.csv` has an mtime of 2026-08-28 04:46:47 UTC
— only ~3 hours after the `2026-08-28T0152Z` snapshot was frozen, far below 24 hours. Positive control: Tinba
was re-processed today (22 October) with the fixed pin, giving 10,902 alerts, byte-identical to the
28 August `tinba.log` — the Table 5 number for Tinba is proven reproducible. zeus/dridex/bittorrent/skype/iot23
have not each been spot-checked for byte-identity separately (they only rely on the time-proximity
argument), so this is not 100% closed if full certainty is wanted — but it is not urgent.

**Fix**: `pin_trails_from_snapshot()` in the notebook (section C.2a) now calls `.touch()` on
`trails.csv`/`trails.csv.confidence` after `copy2()`, refreshing the mtime to the PIN time (not the time the
snapshot was frozen) without changing the content (byte-identical, still verified by SHA-256 after pinning).
The 24-hour window is now counted from when the file actually starts being used. The standalone script
`tools/pin_trails_fresh.py` (written and used on 22 October, outside the notebook) uses the same fix.

**CTU-Normal-32/33 results (after the pin fix, trails verified IDENTICAL before & after each run)**:

| pcap | ground truth | returncode | duration | alert lines | notes |
|---|---|---|---|---|---|
| ctu_normal33 | benign (Win7, user web activity) | 0 | 5 s | **13** | 7 "potential web scanning" (heuristic) + 6 "potential ssti injection" (ad-tracker URLs), all from 10.0.2.15 |
| ctu_normal32 | benign (Kali, browsing 300 top-ranked sites, 3.95 hours) | 0 | 18 s | **123** | 117 from 10.0.2.15, 6 from resolver 192.168.33.254; including blacklist labels "black tds (malicious)" ×6, "android hiddad (malicious)" ×5, "osx atomic (malware)" ×2 |

Determinism (3 runs per capture, same trails): the alert counts are stable (13 and 123 in every run), but the
TRIGGERING packets of the "potential web scanning" heuristic differ from run to run (same count, different
lines) — safe for an aggregate per-host `maltrail_alert_count`, NOT reproducible for per-alert/per-time
analysis.

**Important note for the paper**: `ctu_normal32`/`ctu_normal33` produce "malicious"/"malware" labels from REAL
blacklists/IOCs (not the re-implemented heuristics of Experiment 3) on 100% benign hosts — a different kind of
finding from the false positives of the `infection` heuristic already documented in the paper's §3.5 (that one
is a structural re-implementation, not a real blacklist match). Most likely due to ad-tech/TDS infrastructure
hit while browsing top-ranked sites — worth its own Discussion/Limitations point; not yet written into the
paper at the time of this note.

**Not done**: feeding 117/13 into `layer2_feature_exploration.ipynb` as the `maltrail_alert_count` feature —
checked: that notebook is **SUPERSEDED since 21 October**, and this feature is not used at all in
`compute_behavior_classes.py` (the active methodology), so doing it later would not affect the Experiment 3
numbers already in the paper.
