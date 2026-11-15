# M2: verdict ACCEPT WITH FIXES (zip v1). Due: v2 Sun 15 Nov 18:00

Lead ran here: 177 passed, ruff clean. Rules on eval seed 2002: 17 alerts, all 10 rules fire, 0 false positives; 0 alerts on train. Demo plan ran through run_plan with a fake OpenSearch: validator ok, no `gt` leaked, chain built (26 nodes, 33 edges, 24 host-to-host).

1. [Lead, done] HC-003 WS-08/adm_it exclusion accepted and put in the spec.
2. [Lead, done] api_client now has `list_findings` and `list_alerts`; your `call_api` resolves them (tested).
3. [M2] Test isolation: add a line to your MANIFEST that tests are run per module with PYTHONPATH=common:libs:services/detector (several services have main.py).
4. [M2] Demo plan quality: step s1 (encoded PowerShell) also matches benign WS-08 (adm_it). Its hosts flow into s2/s3, so evidence is mostly benign (7 of 411 events malicious with a whole-day range; 23 of 356 with 11:00-14:00). Add to the chain/evidence notes how M4 should handle it: ranking (hosts with more stages and anomaly) is expected to push WS-08 down. Please add a test of `step_context`/`build_chain` on the generated-style data showing WS-03 outranks WS-08 in the chain edges, or tell Lead if the executor should exclude known admin pairs (needs a spec decision).
5. [M2] Executor caps each step at 500 events but plan `size` default 200: s2 and s3 hit the cap and take the earliest events (sort ts asc), so late malicious events can be cut. Propose in MANIFEST whether to sort or add a time bound from the dependency step; Lead decides.
6. [M2] Real Streamlit and OpenSearch not tested yet: run pages 1 and 3 with `streamlit run services/dashboard/app.py` against a stub API and send a screenshot.
