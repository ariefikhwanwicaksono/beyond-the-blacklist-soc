# Direct verification of the T1046 & T1595.001 graph paths (Experiment 3, Layer 3 escalation)

**Date**: 2026-10-22
**Instance**: `MITTRE` (Neo4j Desktop 2.2.1)
**Connection**: local instance, database `neo4j`, user `neo4j`
**Method**: executed directly in the Query panel of Neo4j Desktop (not simulated or assumed) in a
remote screen-control session; the two queries were typed and run one at a time, and the results were
checked against screenshots (see `t1046_t1595_path_counts.jpg`, `t1046_t1595_path_detail.jpg`).

**Context**: this closes the last "pending" item of Experiment 3 in `main.tex` §2.3/§2.4 — confirming
that the graph path `DetectionStrategy -> Analytic -> DataComponent` actually EXISTS in the KG for both
techniques mapped by Experiment 3 (`port_scanning`/`udp_scanning` -> T1046, `infection` -> T1595.001),
rather than being assumed from the schema. The relationship schema (`DETECTS`, `HAS_ANALYTIC`,
`USES_LOG_SOURCE`) is taken directly from `load_neo4j.py` (not guessed).

## Query 1 — path counts per technique
```cypher
MATCH (t:Technique) WHERE t.id IN ['T1046','T1595.001']
OPTIONAL MATCH (t)<-[:DETECTS]-(ds:DetectionStrategy)-[:HAS_ANALYTIC]->(a:Analytic)-[:USES_LOG_SOURCE]->(dc:DataComponent)
RETURN t.id AS technique, count(DISTINCT ds) AS n_detection_strategies,
       count(DISTINCT a) AS n_analytics, count(DISTINCT dc) AS n_data_components
ORDER BY t.id
```
**Result** (2 rows, completed in 537 ms):

| technique | n_detection_strategies | n_analytics | n_data_components |
|---|---|---|---|
| T1046 | 1 | 4 | 4 |
| T1595.001 | 1 | 1 | 2 |

Both techniques have a complete, non-empty path — the graph path **EXISTS**; a value of `0` would
mean the chain is broken somewhere.

## Query 2 — row detail (run for T1046; the first 11 rows are visible in the screenshot)
```cypher
MATCH (t:Technique) WHERE t.id IN ['T1046','T1595.001']
MATCH (t)<-[:DETECTS]-(ds:DetectionStrategy)-[:HAS_ANALYTIC]->(a:Analytic)-[:USES_LOG_SOURCE]->(dc:DataComponent)
RETURN t.id AS technique, ds.id AS detection_strategy, ds.name AS ds_name,
       a.id AS analytic, dc.id AS data_component, dc.name AS dc_name
ORDER BY t.id, ds.id, a.id, dc.id
```
**Result** (11 rows in total, completed in 167 ms). Example T1046 rows clearly readable in the screenshot:
- `DET0376` ("Behavioral Detection Strategy for Network Service Discovery Across Platforms") ->
  `AN1057` -> Data Component "Network Connection Creation"
- `DET0376` -> `AN1057` -> Data Component "Process Creation"
- `DET0376` -> `AN1058` -> ... (further rows, see `t1046_t1595_path_detail.jpg`)

## Conclusion

The graph path `DetectionStrategy -> Analytic -> DataComponent` is **confirmed to exist** for T1046
(1 detection strategy, 4 analytics, 4 data components) and T1595.001 (1 detection strategy,
1 analytic, 2 data components), run directly against a live Neo4j instance rather than inferred
from the schema. The status "graph-path confirmation (DetectionStrategy->Analytic->DataComponent):
pending" in `main.tex` §2.3/§2.4 can now change to "confirmed" with the numbers above.

**Caveat, to avoid overclaiming**: this confirms that the STRUCTURAL path exists in the KG (the full
schema is connected). It does NOT confirm that Experiment 3 retrieves or displays those detection
strategies/analytics/data components in its window-level evaluation (§3.5) — Experiment 3 currently
stops at technique matching (`port_scanning`/`udp_scanning` -> T1046, `infection` -> T1595.001) and
does not yet trace further to specific analytics/data components per window. That remains future
scope, not something this query resolves.
