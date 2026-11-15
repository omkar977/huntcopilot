# M4: verdict ACCEPT WITH FIXES (zip v1). Due: v2 Sun 15 Nov 18:00

Lead ran here: `PYTHONPATH=common:libs:services/api pytest -q services/api` = 139 passed, 2 skipped (test_m4_http.py needs fastapi, not installed here; one stand-in test skipped because hc_hunt is installed). Ruff clean. Checker PASS.

## Integration result (Lead ran your pipeline with REAL hc_hunt, M3's real model, real rule alerts, M1 eval data seed 2002)
Demo sentence -> source fallback, template lateral_after_powershell, valid plan, run completed, ONE finding: confidence 100, hosts DB-01 FILE-01 WS-03 WS-05 WS-06 WS-08, all 5 stages, chain 30 nodes / 35 edges / 24 host-to-host, 7 recommended actions (isolate x5, block_ip 203.0.113.50, disable_account adm_it), 2 proposals created. adm_it is the stolen account in the scenario, so that action is right. The path works.

## Defects
1. [M4, MUST] WS-08 is in the attack finding (benign adm_it admin script host). M2's note: rank and split by chain components. Your components should separate WS-08 (1 connection, no alerts). Make WS-08 its own low-confidence finding or drop it from this finding's hosts and from isolate_host proposals. Add a test on data shaped like the demo.
2. [M4, MUST] Template step size is still 200 (templates.py line 47). Spec decision C: use 500. In the run, s2 and s3 return exactly 200 (cap hit, evidence cut off).
3. [M4] Only 2 of the 7 recommended actions became proposals. Say in MANIFEST which rule picks them (confidence threshold? cap?). Spec 14 step 7 wants pending proposals, so fine, but isolate_host for 5 hosts when only 4 are really compromised should be reviewed (WS-08 is the 5th wrong one, see item 1).
4. [M4] Run `services/api/tests/test_m4_http.py` for real (fastapi, httpx) and paste the last lines.
5. [M4] Confidence is 100/100 with uncertainty 0.00. Check that your representative window choice (max anomaly) is what spec 10.4 says; a saturated 100 looks odd in the demo. Report what spec 10.4 requires.
6. [Lead, done] api_client has every function your pages call (create_hunt, run_hunt, list_findings(min_confidence, host), list_proposals(status), approve_proposal, reject_proposal, verify_audit, get_state, get_audit, export_case(id, fmt)).
7. [M4] Run pages 2, 4, 5 with `streamlit run services/dashboard/app.py` against your mock api (HC_MOCK_ML=1 HC_MOCK_HUNT=1) and send one screenshot each, or say not run.
