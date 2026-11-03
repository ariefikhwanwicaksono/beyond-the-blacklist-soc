"""
Parse the ATT&CK Enterprise STIX bundle (data/enterprise-attack.json) into
normalised CSV files in data/csv/, ready to be imported into Neo4j.

STIX objects used (see README.md for the full schema explanation):
  x-mitre-tactic          -> tactics.csv
  attack-pattern          -> techniques.csv (teknik + sub-teknik)
  x-mitre-detection-strategy -> detection_strategies.csv
  x-mitre-analytic        -> analytics.csv
  x-mitre-data-component  -> data_components.csv
  relationship            -> several relation files (technique_tactic.csv,
                              subtechnique_of.csv, detects.csv,
                              analytic_datacomponent.csv)

Objects with revoked=True or x_mitre_deprecated=True are DROPPED -- they are
old techniques/objects that have been superseded, not part of the active taxonomy.

Compatibility note: the `from __future__ import annotations` line below is
REQUIRED -- without it, the `str | None` type hints in external_id/
external_url fail on Python < 3.10 (the `X | Y` union syntax is only officially
supported since Python 3.10; before that only typing.Optional[X]).
"""

from __future__ import annotations

import csv
import json
import pathlib

BASE = pathlib.Path(__file__).parent
IN_PATH = BASE / "data" / "enterprise-attack.json"
OUT_DIR = BASE / "data" / "csv"


def is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def external_id(obj: dict, source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name and "external_id" in ref:
            return ref["external_id"]
    return None


def external_url(obj: dict, source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name and "url" in ref:
            return ref["url"]
    return None


def main() -> None:
    if not IN_PATH.exists():
        raise SystemExit(f"{IN_PATH} not found -- run fetch_attck.py first.")

    bundle = json.loads(IN_PATH.read_text())
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects}

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---- tactics.csv ----
    tactics = [o for o in objects if o["type"] == "x-mitre-tactic" and is_active(o)]
    with open(OUT_DIR / "tactics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tactic_shortname", "name", "url"])
        for t in tactics:
            w.writerow([t.get("x_mitre_shortname"), t["name"], external_url(t)])

    # ---- techniques.csv ----
    techniques = [o for o in objects if o["type"] == "attack-pattern" and is_active(o)]
    tech_id_by_stix = {}
    with open(OUT_DIR / "techniques.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "is_subtechnique", "url", "platforms"])
        for t in techniques:
            tid = external_id(t)
            tech_id_by_stix[t["id"]] = tid
            platforms = "|".join(t.get("x_mitre_platforms", []))
            w.writerow([
                tid,
                t["name"],
                str(bool(t.get("x_mitre_is_subtechnique", False))),
                external_url(t),
                platforms,
            ])

    # ---- technique_tactic.csv (from kill_chain_phases) ----
    with open(OUT_DIR / "technique_tactic.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "tactic_shortname"])
        for t in techniques:
            tid = tech_id_by_stix[t["id"]]
            for phase in t.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    w.writerow([tid, phase["phase_name"]])

    # ---- detection_strategies.csv ----
    strategies = [o for o in objects if o["type"] == "x-mitre-detection-strategy" and is_active(o)]
    ds_id_by_stix = {}
    with open(OUT_DIR / "detection_strategies.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["detection_strategy_id", "name", "url"])
        for d in strategies:
            did = external_id(d)
            ds_id_by_stix[d["id"]] = did
            w.writerow([did, d["name"], external_url(d)])

    # ---- analytics.csv ----
    analytics = [o for o in objects if o["type"] == "x-mitre-analytic" and is_active(o)]
    an_id_by_stix = {}
    with open(OUT_DIR / "analytics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["analytic_id", "name", "description", "platforms"])
        for a in analytics:
            aid = external_id(a)
            an_id_by_stix[a["id"]] = aid
            platforms = "|".join(a.get("x_mitre_platforms", []))
            w.writerow([aid, a.get("name", ""), a.get("description", ""), platforms])

    # ---- data_components.csv ----
    components = [o for o in objects if o["type"] == "x-mitre-data-component" and is_active(o)]
    dc_name_by_stix = {c["id"]: c["name"] for c in components}
    with open(OUT_DIR / "data_components.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["data_component_id", "name"])
        for c in components:
            w.writerow([c["id"], c["name"]])

    # ---- detection_strategy_analytic.csv ----
    with open(OUT_DIR / "detection_strategy_analytic.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["detection_strategy_id", "analytic_id"])
        for d in strategies:
            did = ds_id_by_stix[d["id"]]
            for ref in d.get("x_mitre_analytic_refs", []):
                aid = an_id_by_stix.get(ref)
                if aid:
                    w.writerow([did, aid])

    # ---- analytic_datacomponent.csv ----
    with open(OUT_DIR / "analytic_datacomponent.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["analytic_id", "data_component_id", "log_source_name", "channel"])
        for a in analytics:
            aid = an_id_by_stix[a["id"]]
            for ref in a.get("x_mitre_log_source_references", []):
                dc_id = ref.get("x_mitre_data_component_ref")
                if dc_id in dc_name_by_stix:
                    w.writerow([aid, dc_id, ref.get("name", ""), ref.get("channel", "")])

    # ---- relationships: subtechnique-of, detects ----
    with open(OUT_DIR / "subtechnique_of.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["subtechnique_id", "parent_technique_id"])
        for r in objects:
            if r["type"] != "relationship" or r["relationship_type"] != "subtechnique-of":
                continue
            src, tgt = r["source_ref"], r["target_ref"]
            if src in tech_id_by_stix and tgt in tech_id_by_stix:
                w.writerow([tech_id_by_stix[src], tech_id_by_stix[tgt]])

    with open(OUT_DIR / "detects.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["detection_strategy_id", "technique_id"])
        for r in objects:
            if r["type"] != "relationship" or r["relationship_type"] != "detects":
                continue
            src, tgt = r["source_ref"], r["target_ref"]
            if src in ds_id_by_stix and tgt in tech_id_by_stix:
                w.writerow([ds_id_by_stix[src], tech_id_by_stix[tgt]])

    # ---- verification summary ----
    n_sub = sum(1 for t in techniques if t.get("x_mitre_is_subtechnique"))
    print("Parsing finished. CSV files written to", OUT_DIR)
    print("--- Summary (compare with README.md) ---")
    print(f"  Active tactics           : {len(tactics)}")
    print(f"  Active techniques (total): {len(techniques)}")
    print(f"    - parent techniques    : {len(techniques) - n_sub}")
    print(f"    - sub-techniques       : {n_sub}")
    print(f"  Active detection strat. : {len(strategies)}")
    print(f"  Active analytics         : {len(analytics)}")
    print(f"  Active data components   : {len(components)}")


if __name__ == "__main__":
    main()