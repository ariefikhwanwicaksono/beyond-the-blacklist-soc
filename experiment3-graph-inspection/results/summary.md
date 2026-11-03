# Experiment 3 (prototype): Layer2->Layer3 escalation + ATT&CK technique matching
Generated automatically by experiment3_prototype.py -- see that script for the full methodology.

Total windows: 379 (positive=317, negative/benign=62)

| Host | n windows | rare BC | L1 flagged | escalated to L3 | L3 candidate |
|---|---|---|---|---|---|
| tinba_vm | 6 | 2 | 0 | 2 | 2 |
| dridex_vm | 70 | 0 | 0 | 0 | 0 |
| zeus_vm_250 | 109 | 0 | 0 | 0 | 0 |
| zeus_vm_251 | 108 | 0 | 0 | 0 | 0 |
| ctu_normal32 | 48 | 0 | 10 | 0 | 0 |
| ctu_normal33 | 14 | 0 | 3 | 0 | 0 |
| uwf_143.88.5.12 | 21 | 1 | 0 | 1 | 1 |
| uwf_143.88.7.10 | 3 | 2 | 1 | 1 | 1 |

L1 recall (positive windows): 1/317 = 0.003
L1 union L3 recall: 5/317 = 0.016
False positives (benign windows escalated+matched): 0/62

## Important caveats
- The L1 baseline here is ONLY the 3 structural heuristics (port_scanning, udp_scanning, infection), NOT the blacklist/trail list -- a different scope from Table 5 (pilot corpus), which uses a broader methodology.
- dridex_vm, zeus_vm_250 and zeus_vm_251 have 0% of their windows in a rare BC -- they NEVER qualify for escalation to L3, regardless of the technique-matching algorithm.
- The 'infection' heuristic (number of distinct dst_ips to 1 dst_port from 1 src within 30 seconds) fires 10x on ctu_normal32 (benign) purely because ordinary web browsing touches dozens of different CDN IPs on ports 80/443 -- manually confirmed to be the heuristic's real behaviour (read from sensor.py), not a re-implementation bug.
