# MANIFEST
Module: data-infra (generator, ingestor, deploy, dashboard page 7)   Member: M1   Version: v2   Date: 2026-11-14

## Lead defect list (DEFECTS_M1.md, v1) and status
| # | Item | Status |
|---|------|--------|
| 1 | Verify OpenSearch tag 2.17.1 has arm64 | OPEN. The build sandbox cannot reach Docker Hub. `deploy/verify_stack.sh` step 1 runs `docker manifest inspect` and prints the architectures. Result to be pasted here: ______ |
| 2 | ml / api / detector start commands | No change. Kept `python -m uvicorn main:app` (ml, api) and `python -m main` (detector) until M3 / M4 deliver. |
| 3 | Dockerfile.dashboard builds with services/dashboard/requirements.txt | Static check added (test): the Dockerfile copies services/dashboard/ and installs that file. The real build is step 3 of verify_stack.sh. Result: ______ |
| 4 | compose config, up for redis+opensearch+generator+ingestor, eval run, ingest rate, DLQ count | OPEN, needs Docker. `docker compose config` passes in the sandbox. verify_stack.sh steps 2, 4, 5, 6 do the rest. Rate: ______ events/s, DLQ: ______ |
| 5 | kubectl apply --dry-run=client | OPEN, needs kubectl. verify_stack.sh step 7. Output: ______ |
| 6 | Data files by link | Done by the Lead. |

New in v2: `deploy/verify_stack.sh` and two extra tests. No other code changed.

## Implemented (check each item of my work package for this day)
- [x] Generator core: benign model (diurnal curve, Zipf domains, 12 hosts), the 5 hard negatives, deterministic uuid5 ids, JSONL output, unit tests (validity, determinism, volume)
- [x] Generator scenarios: phishing, lateral_movement, credential_dumping, c2, apt_chain; labels.json; redis output mode (XADD hc:telemetry, maxlen 200000 approx); realtime pacing; back-pressure
- [x] Generator control API on 8300 (GET /health, /v1/scenarios, /v1/status, POST /v1/run, X-API-Key, error format) and CLI `python -m generator run|serve|scenarios`
- [x] Ingestor: consumer group `ingestors`, Event validation, bulk index into hc-events-YYYY.MM.DD, hc-events-template (Appendix F), DLQ hc:dlq, ack only after indexing, retry on 429/5xx, stale-message claim, health on 8301, `ingest-file` command, idempotent (_id = event_id)
- [x] deploy/compose/docker-compose.yml: redis, opensearch, generator, ingestor, detector, ml, api, dashboard, mlflow (memory limits of 11.3, healthchecks, depends_on service_healthy, loopback ports except 8501) and .env.example
- [x] Dockerfiles for generator, ingestor, detector, ml, api, dashboard, mlflow in deploy/docker/ (Appendix G pattern)
- [x] deploy/k8s: files 00 to 36 (limits, probes, runAsNonRoot, ConfigMap, Secret example, NodePort 30501)
- [x] Dashboard page 7. File is `deploy/pages/7_Simulation.py` (see Assumptions 13). Copy it to `services/dashboard/pages/7_Simulation.py` when merging.
- [x] deploy/README.md run guide
- [ ] NOT done here: a real `docker compose up`, a run against real Redis and OpenSearch, `kubectl apply --dry-run=client`, the 800 events/s ingest figure against real OpenSearch. See Known issues.

## How to run the tests (exact commands)
From the repository root (skeleton plus these files), Linux or macOS:
```
pip install -r requirements-dev.txt
PYTHONPATH=common:libs:services/generator:services/ingestor:services/dashboard pytest -q services/generator services/ingestor deploy
ruff check --config ruff.toml services deploy
```
Integration test (needs the compose redis and opensearch running and HC_REDIS_URL / HC_OPENSEARCH_URL pointing at them):
```
HC_INTEGRATION=1 PYTHONPATH=common:libs:services/generator:services/ingestor pytest -q services/ingestor/tests/test_ing_integration.py
```
Generate the shared data files (spec 12.3, M3 needs them):
```
PYTHONPATH=common:services/generator python -m generator run --profile benign_train --seed 1001 --out jsonl --jsonl-path data/train.jsonl
PYTHONPATH=common:services/generator python -m generator run --profile eval --scenarios apt_chain --seed 2002 --out jsonl --jsonl-path data/eval.jsonl
```
Run the services: `cd deploy/compose && cp .env.example .env && docker compose up -d --build` (see deploy/README.md).

## Test summary (paste the last lines of pytest)
```
112 passed, 2 skipped in 31.06s
```
Skipped: the kubectl dry-run test (kubectl not installed) and the integration test (needs HC_INTEGRATION=1). ruff: All checks passed.
The sandbox had no network, so pydantic-settings was replaced by a small local stand-in while running the tests. Please re-run with the real packages (`pip install -r requirements-dev.txt`).

## Assumptions made
1. The control API (8300) and the health server (8301) use the Python standard library HTTP server, not FastAPI. Same routes, same JSON, same X-API-Key rule; it keeps the images small and the code testable offline. It can be swapped later.
2. Default start times: benign_train starts 2026-11-11T00:00:00Z and eval starts 2026-11-12T00:00:00Z (different days, so training and evaluation data sit in different daily indices). Override with `--start` or the optional `start` field. Never the wall clock.
3. Default volume is tuned to about 50 000 events (eval: 49 832, benign_train about 49 000) with a peak of 366 events per workstation-hour (`DEFAULT_WS_PEAK`). Servers use 0.4 of that. `events_per_host_hour` replaces the workstation peak.
4. The encoded PowerShell string is the plain base64 of the text `hunt-demo` (aHVudC1kZW1v), as written in 7.4. The benign adm_it scripts are base64 of plain words such as Get-Date.
5. Network events have no process field in the contract, so the c2 "rundll32 as the creator" is represented by one `rundll32.exe` process_create at the start of each beacon run.
6. Every event of an apt_chain run has gt.scenario = apt_chain (stage per event). labels.json lists the sub-parts under `components` (phishing, c2_ws03, lateral_movement, credential_dumping, c2_db01) and the hard negatives with event ids.
7. Hard negatives are in both profiles (they are benign). The benign adm_it psexec run emits no psexesvc.exe event, so HC-006 has nothing to fire on.
8. Extra optional fields on POST /v1/run: `start` and `time_scale` (realtime replay speed, default 60 simulated seconds per second). Extra optional fields on GET /v1/status: `total`, `error`, `labels_path`. No required field was added. A failed run shows state `done` with a non-empty `error`.
9. Only one generator run at a time (a second POST /v1/run gets 409 conflict).
10. Dockerfiles live in deploy/docker/Dockerfile.<service> (the allowed paths for M1 do not include other members' service folders). Start commands for detector (`python -m main`), ml and api (`python -m uvicorn main:app`) are guesses; the last line of each Dockerfile is the one place to change.
11. The OpenSearch tag 2.17.1 was chosen from memory and not checked online. Verify it (and its arm64 variant) with `docker manifest inspect opensearchproject/opensearch:2.17.1` or set OPENSEARCH_IMAGE in .env.
13. Page 7 is shipped as deploy/pages/7_Simulation.py because tools/verify_submission.py does not allow M1 to deliver services/dashboard/pages/7_ (spec 12.1 gives page 7 to M1). The Lead copies it, or adds the prefix `services/dashboard/pages/7_` to the M1 list in ALLOWED. It uses only the standard library (no httpx) and the generator URL and X-API-Key.
12. mlflow starts by default (small, 300 MB). Remove it from the compose file if the VM is short of memory.

## Known issues
- Not run against real Redis, OpenSearch or Docker, only against in-memory fakes (and `docker compose config`, which passes). The first integration round will be the first real test. The ingest rate of 800 events/s was only measured for the CPU part (validation and bulk body building, thousands of events per second); the real figure depends on OpenSearch.
- Note for M2 / Lead: the benign adm_it encoded PowerShell on WS-08 is followed by normal outbound traffic from WS-08. If HC-003 (encoded PowerShell then an outbound connection within 120 s) has no WS-08 / adm_it exclusion like HC-002, it will fire on it. The data is left realistic on purpose.
- The hc:telemetry stream keeps acknowledged entries until the approximate max length (200 000) trims them. The generator waits when unconsumed entries pass 160 000.
- A message that OpenSearch keeps answering with 429 or 5xx is retried forever with back-off (it is never lost, and never sent to the DLQ).
- kubectl dry-run was not possible here (no kubectl). The manifests were checked by a YAML structure test only.
- Compose services detector, ml, api and dashboard need their owners' code and requirements.txt files to build.

## Contract change requests (none or see CHANGE_REQUEST.md)
None. hc_common was not changed.

## New dependencies (name and version range)
- generator: pydantic>=2.5,<3, pydantic-settings>=2.1,<3, redis>=5.0,<6
- ingestor: pydantic>=2.5,<3, pydantic-settings>=2.1,<3, redis>=5.0,<6, opensearch-py>=2.4,<3
- mlflow image: mlflow>=2.9,<3
- tests also use pyyaml (already in requirements-dev.txt)
