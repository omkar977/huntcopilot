# M4 v2: verdict ACCEPT WITH FIXES (round 2). Due: v3 Mon 16 Nov 16:00

Lead ran: `PYTHONPATH=common:libs:services/api pytest -q services/api` = 142 passed, 2 skipped (fastapi missing here). Ruff clean. Checker PASS. Step size 500 confirmed (s2 462, s3 500 events).

## CORRECTIONS to my earlier DEFECTS_M4.md (my mistakes, sorry)
- I said only 2 of 7 actions became proposals. WRONG: all 7 were created (my test script printed the length of a tuple). Your rule (>= 60 gets all actions) works.
- I said the 5 isolate_host targets include a wrong one. WRONG: DB-01, FILE-01, WS-03, WS-05, WS-06 all have malicious events in the data, so these are correct. WS-08 was NOT isolated. Item 3 of the old file is withdrawn.

## Integration result with real hc_hunt + M3 model + real alerts + M1 eval seed 2002
Run completed. Two findings:
1. Conf 100, hosts DB-01 FILE-01 WS-03 WS-05 WS-06 WS-08, 5 stages, chain 31 nodes / 36 edges / 25 host-to-host, 7 actions (isolate x5, block_ip 203.0.113.50, disable_account adm_it), 7 pending proposals.
2. Conf 66, host WEB-01 only, no chain: this is an M3 false positive that surfaced through the hunt.
Not in any finding: DC-01 (1 malicious event, 1 alert).

## Defects
1. [M4, MUST] v2 fix 1 does not work on real data. WS-08 is still in the attack finding. Your `split_weak_hosts` needs the host to have at most ONE peer, but WS-08 connects to FILE-01 (connected + authenticated) and to WEB-01, so 2 peers. Fix: split any host that has NO alerts when its group has alerts (drop the peer condition), or use: no alerts and no window anomaly >= 0.5. Every truly compromised host here has at least one alert, WS-08 has none (alerts: WS-03 8, DB-01 5, FILE-01 1, WS-05 1, WS-06 1, DC-01 1). Add a test with WS-08 having two peers.
2. [M4] The WEB-01 finding (conf 66, no alerts, no chain edges, 1 stage) is noise. Suggest: a component with no alerts and no chain edges gets confidence capped (for example below 50) or is not stored as a finding. Decide and document in MANIFEST. Do NOT change the schema.
3. [M4] DC-01 is not a candidate host. Check why: is it missing from step results (s4 hosts)? Report the cause; if it is a hunt-plan limit, tell Lead.
4. [M4] Run test_m4_http.py with real fastapi, and the three pages with real streamlit. Still not done by anyone. Say not run if not run.
