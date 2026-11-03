// Example queries to try in Neo4j Browser after load_neo4j.py has finished.
// These are NOT part of the automated pipeline -- run them manually, one by one,
// for exploration and sanity checks.

// 1. Number of techniques per tactic (check the v19 taxonomy distribution)
MATCH (te:Technique)-[:PART_OF]->(ta:Tactic)
RETURN ta.name AS tactic, count(te) AS n_techniques
ORDER BY n_techniques DESC;

// 2. Techniques whose detection relies on a "network traffic" data component
// -- the most relevant example for Maltrail (a traffic-based detector)
//
// IMPORTANT: the 6 names below are ALL active v19.2 data components whose name
// contains "Network"/"DNS" (checked manually against the 106 active data
// components, not guessed from a substring). "Network Share Access" is
// deliberately kept SEPARATE: it is the only one of the 6 that is more commonly
// instrumented through host logs (Windows Security/Sysmon) than through pure
// packet capture -- this is a decision about the definition of "network traffic"
// to be discussed in the team (see README.md), not a settled technical fact.
// An older version of this query only checked the substrings 'Network Traffic'/
// 'Network Connection' and silently missed 'Active DNS', 'Passive DNS' and
// 'Network Share Access' -- that was a bug, fixed here.
MATCH (te:Technique)<-[:DETECTS]-(:DetectionStrategy)-[:HAS_ANALYTIC]->(an:Analytic)
      -[:USES_LOG_SOURCE]->(dc:DataComponent)
WHERE dc.name IN [
    'Network Connection Creation', 'Network Traffic Content',
    'Network Traffic Flow', 'Active DNS', 'Passive DNS'
    // , 'Network Share Access'  -- uncomment if the definition of "network
    //   traffic" is relaxed to include share-access logs (see README)
]
RETURN DISTINCT te.id, te.name
ORDER BY te.id
LIMIT 25;

// 3. Which data components are used most often by analytics
// (to see which could serve as a "bridge" between Maltrail alerts and techniques)
MATCH (:Analytic)-[:USES_LOG_SOURCE]->(dc:DataComponent)
RETURN dc.name, count(*) AS n_analytics_using
ORDER BY n_analytics_using DESC
LIMIT 20;

// 4. Full chain from one data component up to the tactic
// -- the relational pattern behind "Differentiator 2" (relational KG vs
// Kalutharage's threshold table): DataComponent -> Analytic ->
// DetectionStrategy -> Technique -> Tactic
MATCH path = (dc:DataComponent {name: 'Network Traffic Content'})
             <-[:USES_LOG_SOURCE]-(:Analytic)
             <-[:HAS_ANALYTIC]-(:DetectionStrategy)
             -[:DETECTS]->(te:Technique)
             -[:PART_OF]->(ta:Tactic)
RETURN path
LIMIT 10;

// 5. Sub-techniques of one specific parent technique (example: T1055)
MATCH (sub:Technique)-[:SUBTECHNIQUE_OF]->(parent:Technique {id: 'T1055'})
RETURN sub.id, sub.name
ORDER BY sub.id;
