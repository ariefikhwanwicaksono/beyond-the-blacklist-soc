# Experiment 1 — ATT&CK into Neo4j

Foundation experiment for the SOC + Knowledge Graph + MITRE ATT&CK paper (originally targeted at
ACIG). Goal: build a *knowledge graph* base from the official MITRE ATT&CK taxonomy in Neo4j — not
only tactics/techniques, but also MITRE's official **Detection Strategies** and **Analytics**, which
turn out to provide a semantic bridge to the data/log types (including network traffic) that are
directly relevant to Maltrail.

Status: parsing was fully tested in a cloud sandbox (the numbers below are verified). Writing to
Neo4j (`load_neo4j.py`) was NOT tested against a live Neo4j server at first — that sandbox could run
neither Neo4j nor Docker. The Cypher follows the standard pattern (UNWIND + MERGE), but the first step
after running the script is to **compare the printed verification numbers with the table in
"Verification numbers" below** and report any difference.

## Database isolation — use a new DBMS, not an existing one

If your Neo4j Desktop already has an older DBMS (especially one configured with certificates/encrypted
connections, or holding data from other projects), **do not load this experiment's graph into it**.
Create a new local DBMS dedicated to this experiment:

1. In Neo4j Desktop, click "New" / "+" to add a new **Local DBMS** (not a new "database" inside the
   same DBMS) — this creates a completely separate server instance: its own Bolt port, its own data
   folder, its own configuration (including certificates), and it does not touch the old DBMS at all.
2. Name it, for example, `attck-kg-experiment`, set a password, and click Start.
3. Click the instance to see its Bolt URI (usually `bolt://localhost:7688`, or another port if `7687`
   is already used by your old DBMS) — use this URI, NOT `bolt://localhost:7687`, when setting
   `NEO4J_URI` in step 4 of "How to run" below.

Why this matters: the Python driver (`neo4j` package) used by `load_neo4j.py` only talks Bolt as a
client — it never touches certificate files or server configuration, so technically it cannot "break"
the certificates of your old DBMS [HIGH CONFIDENCE, based on Neo4j's client-server architecture]. The
real risk is **data mixing**: `load_neo4j.py` uses `MERGE` (so it deletes nothing), but if it is run
against a DBMS that already holds other project data, this ATT&CK graph gets mixed into the same
database — which makes it hard to clean up or export this experiment's graph separately later, e.g.
for a paper appendix. A new DBMS avoids that entirely, at a small setup cost.

If your old DBMS requires encrypted connections (URI scheme `neo4j+s://` or `bolt+s://`, not plain
`bolt://`) and you still want to use it: this script will fail to connect (it breaks nothing, it is
just a handshake error) until you change `NEO4J_URI` to the matching scheme. The recommendation
remains: use a new DBMS — simpler and safer for the paper's reproducibility.

## Key finding — candidate Differentiator #6

During parsing we found that ATT&CK Enterprise v19.2 (downloaded 23 August 2026,
`x_mitre_version: "19.2"`, `modified: 2026-08-05`) now has two STIX object types that did NOT yet exist
when earlier work (including Kalutharage & Nerella 2025, and the whole SEPSES/AgCyRAG line) was
published:

- **Detection Strategy** (697 objects — exactly 1 per active technique)
- **Analytic** (1758 objects) — each analytic contains a description of the detection logic plus a
  **list of specific data sources/logs** (`x_mitre_log_source_references`) that serve as evidence for
  that technique.

Of the 1758 analytics, **544 (30.9%) refer to network-traffic data components**. This means MITRE
itself now provides an official mapping: *which data/log* → *analytic* → *detection strategy* →
*technique* → *tactic*. This chain can serve as an official bridge between Maltrail alerts and ATT&CK
techniques — far more defensible as the basis of a relational KG than Kalutharage's ad-hoc threshold
table, and stronger as a validation basis than their 2 manual examples. **Because this feature is very
new, most likely none of the papers in the 11 earlier Scopus queries use it** — to be discussed with
Dedy & Prof. Ashari as a candidate sixth differentiator.

### Exact definition of "network traffic" — a decision for the team

There are 6 active v19.2 data components whose name contains Network/DNS: `Network Connection
Creation`, `Network Traffic Content`, `Network Traffic Flow`, `Active DNS`, `Passive DNS`, and
`Network Share Access`. The **544/30.9%** figure is computed from ALL 6 of these components.

`Network Share Access` (SMB share access events) is deliberately flagged separately: it is the only one
of the 6 that is more commonly instrumented through host logs (Windows Security/Sysmon) than through
pure packet capture in the style of Maltrail. If `Network Share Access` is excluded (a stricter
definition of "network traffic", only what is observable from raw traffic), the figure becomes
**534/1758 = 30.4%** — `Network Share Access` alone accounts for the whole difference of 10 analytics
(`Passive DNS` turns out to add no new analytics at all; every analytic mentioning it is already
counted through another component).

This is purely a definitional decision for the paper, not a technical issue — 30.9% and 30.4% are both
defensible depending on how "network traffic" is defined. Section 5 of `explore_kg.ipynb` computes both
definitions side by side so that the difference is visible, rather than a single final number.

**A bug that occurred (23 August 2026, fixed):** the initial cross-check query in `explore_kg.ipynb`
and in `cypher/sample_queries.cypher` only checked the substrings `'Network Traffic'`/`'Network
Connection'`/`'Active DNS'`, which silently missed `Passive DNS` and `Network Share Access` — giving
534/30.4% when the intention was to reproduce 544/30.9%. Both files were fixed to use an explicit list
of names (`dc.name IN [...]`) rather than a substring guess.

Note of caution: the analytic descriptions (`x-mitre-analytic.description`) appear to have been partly
generated with AI assistance by the MITRE team (their language style is consistent with that) — this
should be checked directly against MITRE ATT&CK's official documentation on how Detection
Strategies/Analytics are authored before claiming them in the paper as "expert knowledge" without
qualification. [NEEDS VERIFICATION]

## Graph schema

```
(:Tactic {shortname, name, url})
(:Technique {id, name, is_subtechnique, url, platforms})
(:DetectionStrategy {id, name, url})
(:Analytic {id, name, description, platforms})
(:DataComponent {id, name})

(:Technique)-[:PART_OF]->(:Tactic)
(:Technique)-[:SUBTECHNIQUE_OF]->(:Technique)
(:DetectionStrategy)-[:DETECTS]->(:Technique)
(:DetectionStrategy)-[:HAS_ANALYTIC]->(:Analytic)
(:Analytic)-[:USES_LOG_SOURCE {log_source_name, channel}]->(:DataComponent)
```

This is a genuine multi-entity relational KG (not a threshold table like Kalutharage's) — directly
addressing Differentiator #2 of the research framework.
`(:Analytic)-[:USES_LOG_SOURCE]->(:DataComponent)` is the most important relationship for the next step
(connecting Maltrail alerts to the relevant `DataComponent` nodes).

## How to run (on a Mac)

1. Make sure Neo4j Desktop is running and you know its Bolt URI (usually `bolt://localhost:7687`),
   username (`neo4j`) and database password.

2. Create a virtual environment and install the dependencies:
   ```bash
   cd layer3-attck-neo4j
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Download the ATT&CK data and parse it into CSV:
   ```bash
   python3 fetch_attck.py
   python3 parse_attck.py
   ```
   Compare the printed summary with the "Verification numbers" table below. `fetch_attck.py` is pinned
   to ATT&CK v19.2, the version used in the paper, so the numbers should match exactly.

4. Set the Neo4j credentials and load into the database:
   ```bash
   export NEO4J_URI="bolt://localhost:7687"
   export NEO4J_USER="neo4j"
   export NEO4J_PASSWORD="<your Neo4j Desktop password>"
   python3 load_neo4j.py
   ```
   The script is safe to run repeatedly (it uses `MERGE`, not `CREATE`).

5. Open Neo4j Browser and try the queries in `cypher/sample_queries.cypher` one by one to explore the
   graph visually.

## Verification numbers

Parsing results, tested against ATT&CK Enterprise v19.2 data (downloaded 23 August 2026):

| Entity | Count |
|---|---|
| Active tactics | 15 |
| Active techniques (total) | 697 |
| — parent techniques | 222 |
| — sub-techniques | 475 |
| Active detection strategies | 697 |
| Active analytics | 1758 |
| Active data components | 106 |
| `PART_OF` relationships (technique→tactic) | 872 |
| `SUBTECHNIQUE_OF` relationships | 475 |
| `DETECTS` relationships | 697 |
| `HAS_ANALYTIC` relationships | 1745 |
| `USES_LOG_SOURCE` relationships (analytic→data component) | 4182 |

These 15 tactics include **"Stealth"** and **"Defense Impairment"** (TA0112) — the split of the old
"Defense Evasion" tactic, confirmed directly from the official data (in the early research framework
their exact names were still marked "to be checked").

`PART_OF` (872) is larger than the number of techniques (697) because some techniques belong to more
than one tactic at once — this is the correct behaviour of the ATT&CK taxonomy, not a bug.

### Bug found & fixed (23 August 2026): USES_LOG_SOURCE relationships silently lost

When the first version of `load_neo4j.py` was run against a local Neo4j, the `USES_LOG_SOURCE` count
came out as **4170, not 4182** as in the CSV. This was traced and confirmed on the real data: the cause
was the Cypher pattern `MERGE (a)-[r:USES_LOG_SOURCE]->(c)`, which treats the relationship identity as
the (Analytic, DataComponent) pair alone, while `log_source_name`/`channel` were only `SET` afterwards.
There turned out to be 11 (analytic, data component) pairs referenced through more than one specific
log source/channel at once (example: one analytic needs evidence from `WinEventLog:Sysmon EventCode=1`
**and** `WinEventLog:Security EventCode=4688` for the same DataComponent) — so the second row overwrote
the first instead of creating a new relationship, silently losing 12 rows of log-source data (no error).

Fixed: `log_source_name`/`channel` are now part of the `MERGE` pattern itself, not just `SET` afterwards,
so every distinct log source/channel combination gets its own relationship. Re-verified directly from
the real CSV (not just by reading the code): 4182 CSV rows = 4182 truly unique (analytic, data component,
log_source_name, channel) combinations — so 4182 in the table above is the correct upper bound, and the
fixed version should reach it exactly.

**The script is safe to re-run** (idempotent through `MERGE`) — if the old buggy version was already
loaded, simply run `python3 load_neo4j.py` again with the fixed file; the missing relationships are
added automatically without duplicating the correct ones.

Two verification queries that were previously missing were also added (a gap in the verification
script, not in the data): `SUBTECHNIQUE_OF` and `HAS_ANALYTIC` relationships — previously their CSVs were
loaded, but the resulting relationship counts were never checked back. Both were later confirmed on the
live instance (475 and 1745, see `results/neo4j_verification_log.md`).

## Next steps (not yet done at the time of writing)

- Define the node/edge schema for the Maltrail side: `(:Alert)`, `(:Host)`, aggregation over time — so it
  can be connected to the `(:DataComponent)` nodes already in this graph.
- Test `load_neo4j.py` on Neo4j Desktop and report the verification numbers back, to make sure no Cypher
  bug slipped through the sandbox testing.
- Design ground-truth validation (still an open decision in the research framework) — there is now a
  candidate basis: matching through the official `DataComponent`, not a free LLM guess.
