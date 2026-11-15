# MANIFEST
Module: detect (hc_detect, hc_hunt, detector, dashboard pages 1 and 3)   Member: M2   Version: v2   Date: 2026-11-14

## Implemented (check each item of my work package for this day)
- [x] Day 1: rule engine (single, threshold, sequence, periodicity) as pure functions, YAML loader and validation, 10 rules, tests (positive and negative per rule)
- [x] Day 2: detector service (batch and follow modes, OpenSearch reads, upsert by alert_id, publish to hc:alerts, health on 8200, endpoints of 6.4)
- [x] Day 2: hc_hunt validator (V1 to V10, dst_hosts addendum) and executor (DSL builder tested without OpenSearch, gt excluded, wildcards never user supplied)
- [x] Day 3: build_chain and chain_to_dot with tests (node cap 80, deterministic output, valid DOT checked with graphviz)
- [x] Day 3: dashboard pages 1_Alert_Queue.py and 3_Attack_Chain.py (smoke tested with a fake streamlit)
- [ ] COULD: rule hot-reload (not done)

## How to run the tests (exact commands)
From the repo root (skeleton plus these files), Python 3.10 or 3.11:
    PYTHONPATH=common:libs:services/detector pytest -q libs/hc_detect libs/hc_hunt services/detector
    ruff check --config ruff.toml libs/hc_detect libs/hc_hunt services
Tests are run per module (not all services at once) with PYTHONPATH=common:libs:services/detector, because several services have a main.py and a bare `import main` would be ambiguous. The M2 tests never import `main` by name.
Detector: `cd services/detector && python main.py` (needs HC_API_KEY, OpenSearch and Redis).

## Test summary (paste the last lines of pytest)
See pytest_output.txt.

## Assumptions made
- HC-003 also has the WS-08 and adm_it exclusion (Section 8 lists none); otherwise hard negative 1 would fire it.
- startswith and endswith are case sensitive; contains and regex are case insensitive (Section 5.6). A list field such as tags matches when any element matches.
- A sequence step must be strictly later in time than the previous step; at most 50 open chains per group (oldest dropped); rule level exclusions apply to every step. Duplicate alert_ids are emitted once.
- Alert created_at equals ts_last so the engine stays deterministic. The detector upsert keeps status and created_at of existing alerts.
- Follow mode re-evaluates the 2 hours before the newest event timestamp (not the wall clock, the data is synthetic).
- run-batch returns alerts_created (newly created), alerts_total, events_evaluated and per_rule (all alerts found per rule).
- The detector creates hc-alerts with keyword fields (host, rule_id, status) if missing, so M4 can use term filters. It uses a stdlib HTTP server and requires X-API-Key on all but /health (401 with code invalid_request).
- Validator: extra code V0 for the field allow-list. net.dst_ip is an ip field, so contains is rejected and startswith needs a dotted prefix (executor turns 10.10. into a CIDR term). Numeric fields need numeric values. Unknown stages are warnings.
- Executor: group_by adds a terms aggregation (results are not returned, StepResult is unchanged); evidence per step is capped at 500; event_count is the number of evidence events. run_plan validates again and raises PlanValidationError. Helper step_context(events) gives hosts, users, dst_ips and dst_hosts (M4 needs dst_hosts for 10.4).
- Chain: no user nodes (Edge has no label field), no dropped edges, inbound connections point at the local host, spawned edges skipped when parent_pid is 0.
- Pages call api_client through hc_hunt.views.call_api, which tries list_findings/get_findings/findings and list_alerts/get_alerts/alerts and passes only accepted arguments. Lead: please confirm the real names.

## Defect list answers (DEFECTS_M2.md)
- 3: done, see the test commands above.
- 4: test_demo_evidence.py runs the demo plan on fixture data. s1 does match the benign WS-08 admin script (hosts WS-03 and WS-08), but WS-03 has more outgoing chain edges (host-to-host and authenticated to FILE-01, DB-01, WS-05, WS-06) than WS-08 (one connection), and its host risk is higher. Advice for M4: do not drop WS-08 in the executor; rank findings so hosts with more stages, more alerts and higher anomaly come first, and split components with build_chain edges (WS-08 ends up in its own small component with 1 stage and no alerts because HC-002/HC-004 exclude it). If Lead prefers an executor-level exclusion of known admin pairs, that is a spec decision (it would hide a real stolen admin account), so it is NOT implemented.
- 5: proposal for Lead to decide (not implemented, contract unchanged): option A (recommended) add a time bound from the dependency step, so s2 and s3 query from the earliest event of s1 to the end of the plan range, plus sort by ts asc as now; option B sort descending when a step hits its size cap; option C raise default size to 500 in templates. Cheapest and safest: C now, A as a follow-up in run_plan (small change, needs no schema change). Until decided, a step that returns exactly `size` events may be truncated; run_plan logs event counts per step.
- 6: NOT done. Streamlit is not installed in this session and package installs are blocked, so I could not run `streamlit run` or take a screenshot. Pages are tested with a fake streamlit only. Whoever has Streamlit should run pages 1 and 3 against the stub API.

## Known issues
- fastapi, streamlit, opensearch-py and redis were not installed where this was written, so the pages and service were tested with fakes only; nothing was run against real OpenSearch, Redis or Streamlit. Integration round 1 should check this.
- Rules were tested on the 288 event fixture and synthetic events, not on M1 generator data yet.

## Contract change requests (none or see CHANGE_REQUEST.md)
none

## New dependencies (name and version range)
services/detector/requirements.txt: pydantic>=2.5,<3, pydantic-settings>=2.1,<3, pyyaml>=6.0,<7, opensearch-py>=2.4,<3, redis>=5.0,<6
