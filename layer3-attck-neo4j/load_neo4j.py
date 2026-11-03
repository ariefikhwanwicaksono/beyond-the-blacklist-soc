"""
Load the CSV files produced by parse_attck.py (data/csv/) into Neo4j via the Bolt driver.

Credentials are read from environment variables, NOT hard-coded:
    NEO4J_URI       (default: bolt://localhost:7687)
    NEO4J_USER      (default: neo4j)
    NEO4J_PASSWORD  (required -- no default)

Example (zsh, in a macOS terminal, before running this script):
    export NEO4J_URI="bolt://localhost:7687"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="your-neo4j-desktop-password"
    python3 load_neo4j.py

Graph schema created (see README.md for explanation and rationale):

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

All writes use MERGE -- safe to run repeatedly (idempotent);
re-running the script does not create duplicate nodes/relationships.
"""

import csv
import os
import pathlib
import sys

from neo4j import GraphDatabase

BASE = pathlib.Path(__file__).parent
CSV_DIR = BASE / "data" / "csv"

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD")

BATCH_SIZE = 500


def read_csv(name: str) -> list[dict]:
    path = CSV_DIR / name
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def batched(rows: list[dict], size: int = BATCH_SIZE):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


CONSTRAINTS = [
    "CREATE CONSTRAINT tactic_shortname IF NOT EXISTS "
    "FOR (t:Tactic) REQUIRE t.shortname IS UNIQUE",
    "CREATE CONSTRAINT technique_id IF NOT EXISTS "
    "FOR (t:Technique) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT detstrategy_id IF NOT EXISTS "
    "FOR (d:DetectionStrategy) REQUIRE d.id IS UNIQUE",
    "CREATE CONSTRAINT analytic_id IF NOT EXISTS "
    "FOR (a:Analytic) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT datacomponent_id IF NOT EXISTS "
    "FOR (c:DataComponent) REQUIRE c.id IS UNIQUE",
]


def load_tactics(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (t:Tactic {shortname: row.tactic_shortname})
        SET t.name = row.name, t.url = row.url
        """,
        rows=rows,
    )


def load_techniques(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (t:Technique {id: row.technique_id})
        SET t.name = row.name,
            t.is_subtechnique = (row.is_subtechnique = 'True'),
            t.url = row.url,
            t.platforms = split(row.platforms, '|')
        """,
        rows=rows,
    )


def load_technique_tactic(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (te:Technique {id: row.technique_id})
        MATCH (ta:Tactic {shortname: row.tactic_shortname})
        MERGE (te)-[:PART_OF]->(ta)
        """,
        rows=rows,
    )


def load_subtechnique_of(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (sub:Technique {id: row.subtechnique_id})
        MATCH (parent:Technique {id: row.parent_technique_id})
        MERGE (sub)-[:SUBTECHNIQUE_OF]->(parent)
        """,
        rows=rows,
    )


def load_detection_strategies(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (d:DetectionStrategy {id: row.detection_strategy_id})
        SET d.name = row.name, d.url = row.url
        """,
        rows=rows,
    )


def load_detects(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (d:DetectionStrategy {id: row.detection_strategy_id})
        MATCH (t:Technique {id: row.technique_id})
        MERGE (d)-[:DETECTS]->(t)
        """,
        rows=rows,
    )


def load_analytics(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (a:Analytic {id: row.analytic_id})
        SET a.name = row.name,
            a.description = row.description,
            a.platforms = split(row.platforms, '|')
        """,
        rows=rows,
    )


def load_detection_strategy_analytic(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (d:DetectionStrategy {id: row.detection_strategy_id})
        MATCH (a:Analytic {id: row.analytic_id})
        MERGE (d)-[:HAS_ANALYTIC]->(a)
        """,
        rows=rows,
    )


def load_data_components(tx, rows):
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (c:DataComponent {id: row.data_component_id})
        SET c.name = row.name
        """,
        rows=rows,
    )


def load_analytic_datacomponent(tx, rows):
    # IMPORTANT: log_source_name & channel MUST be part of the MERGE pattern, not
    # only SET afterwards. One analytic can refer to the SAME DataComponent through
    # more than one specific log source/channel (e.g. via WinEventLog:Sysmon
    # EventCode=1 AND WinEventLog:Security EventCode=4688 at the same time). If those
    # properties are only SET, MERGE matches the relationship on
    # (a)-[:USES_LOG_SOURCE]->(c) alone, so the second row "overwrites" the first
    # instead of creating a new relationship -- the other log source silently
    # disappears. The first version of this script had exactly this bug (caught on
    # real data: 4182 CSV rows vs only 4170 relationships in Neo4j) -- see README.md.
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (a:Analytic {id: row.analytic_id})
        MATCH (c:DataComponent {id: row.data_component_id})
        MERGE (a)-[r:USES_LOG_SOURCE {
            log_source_name: row.log_source_name,
            channel: row.channel
        }]->(c)
        """,
        rows=rows,
    )


STEPS = [
    ("tactics.csv", load_tactics),
    ("techniques.csv", load_techniques),
    ("technique_tactic.csv", load_technique_tactic),
    ("subtechnique_of.csv", load_subtechnique_of),
    ("detection_strategies.csv", load_detection_strategies),
    ("detects.csv", load_detects),
    ("analytics.csv", load_analytics),
    ("detection_strategy_analytic.csv", load_detection_strategy_analytic),
    ("data_components.csv", load_data_components),
    ("analytic_datacomponent.csv", load_analytic_datacomponent),
]

VERIFY_QUERIES = [
    ("Tactic", "MATCH (n:Tactic) RETURN count(n) AS c"),
    ("Technique (all)", "MATCH (n:Technique) RETURN count(n) AS c"),
    ("Parent technique", "MATCH (n:Technique {is_subtechnique: false}) RETURN count(n) AS c"),
    ("Sub-technique", "MATCH (n:Technique {is_subtechnique: true}) RETURN count(n) AS c"),
    ("DetectionStrategy", "MATCH (n:DetectionStrategy) RETURN count(n) AS c"),
    ("Analytic", "MATCH (n:Analytic) RETURN count(n) AS c"),
    ("DataComponent", "MATCH (n:DataComponent) RETURN count(n) AS c"),
    ("Rel. PART_OF", "MATCH ()-[r:PART_OF]->() RETURN count(r) AS c"),
    ("Rel. SUBTECHNIQUE_OF", "MATCH ()-[r:SUBTECHNIQUE_OF]->() RETURN count(r) AS c"),
    ("Rel. DETECTS", "MATCH ()-[r:DETECTS]->() RETURN count(r) AS c"),
    ("Rel. HAS_ANALYTIC", "MATCH ()-[r:HAS_ANALYTIC]->() RETURN count(r) AS c"),
    ("Rel. USES_LOG_SOURCE", "MATCH ()-[r:USES_LOG_SOURCE]->() RETURN count(r) AS c"),
]


def main() -> None:
    if not PASSWORD:
        sys.exit(
            "NEO4J_PASSWORD is not set. Set the environment variable first; "
            "see the example at the top of this file."
        )
    if not CSV_DIR.exists():
        sys.exit(f"{CSV_DIR} not found -- run fetch_attck.py and then parse_attck.py first.")

    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    driver.verify_connectivity()
    print(f"Connected to {URI} as {USER}")

    with driver.session() as session:
        print("Creating constraints...")
        for stmt in CONSTRAINTS:
            session.run(stmt)

        for filename, loader in STEPS:
            rows = read_csv(filename)
            print(f"Loading {filename} ({len(rows)} rows)...")
            for chunk in batched(rows):
                session.execute_write(loader, chunk)

        print("\n--- Node & relationship counts in Neo4j ---")
        for label, query in VERIFY_QUERIES:
            result = session.run(query).single()
            print(f"  {label:<24s}: {result['c']}")

    driver.close()
    print("\nDone. Compare the numbers above with README.md, section 'Verification numbers'.")


if __name__ == "__main__":
    main()