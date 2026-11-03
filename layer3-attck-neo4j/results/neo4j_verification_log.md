# Direct verification of 2 Neo4j edge counts — SUBTECHNIQUE_OF & HAS_ANALYTIC

**Date**: 2026-10-22
**Instance**: `MITTRE` (Neo4j Desktop 2.2.1), ID `fb7ac9e0-71c5-4e62-be84-8fc9c345cf81`
**Connection URI**: `neo4j://127.0.0.1:7687`, database `neo4j`, user `neo4j`
**Method**: executed directly in the Query panel of Neo4j Desktop (not simulated or assumed) in a
remote screen-control session; the two queries were typed and run one at a time, and the results were
checked against screenshots taken before and after each run (see `subtechnique_of_475.jpg`,
`has_analytic_1745.jpg`).

## Query 1
```cypher
MATCH ()-[r:SUBTECHNIQUE_OF]->() RETURN count(r) AS c
```
**Result**: `c = 475`. Completed in 64 ms.

## Query 2
```cypher
MATCH ()-[r:HAS_ANALYTIC]->() RETURN count(r) AS c
```
**Result**: `c = 1745`. Completed in 57 ms.

## Conclusion

Both numbers **match exactly** the values already reported in Table 7 of `main.tex` (475 and 1,745).
Those numbers were not invented; they had simply not been re-confirmed against a live Neo4j instance
until this verification. The status of both relationships in Table 7 can now change from "awaiting
re-run" to "verified", and the corresponding edges in Figure 3 (KG schema) change from dashed/orange
to solid, consistent with the 3 other relationships verified earlier.

The queries are identical to those in `load_neo4j.py` (`VERIFY_QUERIES`).
