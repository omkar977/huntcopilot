# MANIFEST
Module: ml (libs/hc_ml, services/ml, dashboard page 6)   Member: M3   Version: v2   Date: 2026-11-15

## Response to DEFECTS_M3 (v1 review)
1. Tuning on real data: NOT done. The M1 train and eval files were not in what I received (only the defects note), so I could not reproduce your numbers. Added per-role baselines as an opt-in: `python -m hc_ml train ... --per-group` (service: env HC_ML_PER_GROUP=1). Separate scaler, forests, Markov chain, p50/p99 and z-baseline for workstations and for servers (FILE-01, DB-01, DC-01, WEB-01); a group with too little data falls back to the global part; deterministic. On my synthetic data it was WORSE than global (precision 0.16 to 0.18, recall 0.61 to 0.70, 5.3 to 7.2 FP per host-day, on seeds 2002, 3003, 4004), because my synthetic servers do not differ much from workstations and have few windows. So it is OFF by default. Lead: please run train with and without `--per-group` on seed 1001, evaluate on 2002 and 3003, and send me both result tables; I will tune from those.
2. test_svc_api.py: still not run (fastapi missing on my machine). Please paste your run.
3. No API key: accepted. Page 6 sends no secrets (no headers, no keys).
4. Start command: ml_main imports only ml_store and ml_tracking from services/ml, so `python -m uvicorn ml_main:app --port 8100` with PYTHONPATH=common:libs:services/ml should start. Not run here (no uvicorn).
5. Page 6: every error path goes through st.error and the whole page is wrapped so no traceback shows. Not run with streamlit, no screenshot.
6. Added services/ml/tests/test_svc_schemas.py (builds ScoredWindow and ScoreBreakdown from my output). Not run here (pydantic missing); it skips itself if pydantic is missing.
7. mlflow: not run (not installed here, no network). Logging is best effort and cannot break training. Please say whether it worked.

## Implemented (check each item of my work package for this day)
- [x] Day 1 MUST: windowing (15-minute UTC host windows), all 22 features with the exact names of Section 9.1, StandardScaler, 5 Isolation Forests (seeds seed..seed+4, 200 trees), normalisation by training p50/p99, Markov sequence model, train and evaluate from JSONL with no OpenSearch (`python -m hc_ml`), unit tests
- [x] Day 2 MUST: ml REST service (health, train, windows, confidence, evaluate, models/current), read-only OpenSearch reads, model files in HC_MODEL_DIR/current (isoforest_0..4.joblib, scaler.joblib, markov.json, meta.json)
- [x] Day 2 MUST: confidence function and deterministic rationale (Section 9.3)
- [x] Day 2 SHOULD: MLflow logging to the local file store (best effort); KMeans clustering with silhouette
- [x] Day 3 SHOULD: dashboard page 6 (model meta, Evaluate button, metrics, z-score view, MLflow link)
- [ ] Day 3 MUST tuning: recall target met on my synthetic data; precision and false-positive targets NOT met (see Known issues). Must be re-tuned on the real M1 generator data.

Files: libs/hc_ml/**, services/ml/**, services/dashboard/pages/6_Model_and_Data.py.

## How to run the tests (exact commands)
    pip install -r services/ml/requirements.txt -r requirements-dev.txt
    PYTHONPATH=common:libs:services/ml pytest -q libs/hc_ml services/ml
Service API tests (services/ml/tests/test_svc_api.py) need fastapi and httpx and skip themselves if missing.

## Test summary (paste the last lines of pytest)
Not run with real pytest. The offline build machine could not install pytest, pydantic, fastapi or ruff (no network).
I ran the library tests (36) and store tests (7) with a small stand-in runner: 43 passed (see pytest_output.txt).
NOT executed by me: services/ml/tests/test_svc_api.py, test_svc_schemas.py, ml_main.py itself, page 6, and ruff. Please run the command above first.

## Assumptions made
1. Metrics on my own test-only generator (libs/hc_ml/tests/synth.py, 12 hosts, 24 h, about 24 000 train events): recall 0.87, 0.96, 0.91 on three eval seeds (target 0.85, met). Precision 0.31, 0.29, 0.21 (target 0.60, missed). False positives per host-day 3.75, 4.58, 6.42 (target 3, missed). The M1 generator will differ, so these are indicative only.
2. Performance on 50 835 events: training 1.1 s, scoring 1.0 s (target 15 s).
3. Rationale label follows the rule (80 or more high, 60 to 79 medium, below 60 low), so the spec example "medium-high" is rendered "medium".
4. z-scores use std floored at 0.1 and are capped at 99, because many count features have zero variance in benign training. hour_sin and hour_cos are never listed as top features.
5. Windows are whole 15-minute windows: the requested time_range is widened to window boundaries, so a window's event_ids can include events just outside the range.
6. Criticality of an unknown host counts as 1 of 5. Coverage is 0 when there are no expected stages. A window with no event transitions gets sequence score 0.
7. rare_* scores use Laplace smoothing: -log((count + 1) / (total + distinct + 1)). internal destinations are counted by dst_host, else dst_ip.
8. The ml service has no API key check (internal service, port published on 127.0.0.1 only).
9. Module name for the Dockerfile pattern is `ml_main` (unique, so it does not clash with other services' main.py): `CMD python -m ml_main`, PYTHONPATH=/app/common:/app/libs:/app/services/ml.
10. With --per-group the group parts are saved in current/groups/<workstation|server>/ (same file names); the root files stay the spec layout. meta.json also holds the training statistics (process frequencies, known domains, feature means and stds). model_id is a uuid4 hex.
11. Evaluation host-days = number of hosts times max(span in days, 1).
12. Page 6 calls the ml service through its own small helper because ml endpoints are not in api_client.py. The Lead may move them. Env: HC_ML_URL, HC_MLFLOW_UI_URL (optional).

## Known issues
- Precision and false-positive targets of Section 1.7 are missed on my synthetic data. Things tried and rejected: shrinking sequence scores of short windows, log transform of counts (both made it worse). Next steps once M1 data exists: re-check on 2 or 3 seeds, compare benign-heavy windows, and consider a separate model per host role (workstation vs server). The 0.5 threshold and the weights are fixed by the spec and were not changed.
- Isolation Forest cannot react to features that are constant in benign training (for example n_cred_tools). Attacks are still caught through rare_* scores and the Markov model, and these counters still appear as top features.
- Not verified here: pydantic validation of the service responses against hc_common.schemas, FastAPI behaviour, MLflow logging, ruff.

## Contract change requests (none or see CHANGE_REQUEST.md)
None.

## New dependencies (name and version range)
numpy>=1.26,<3; pandas>=2.0,<4; scikit-learn>=1.3,<2; joblib>=1.3,<2; fastapi>=0.110,<1.0; uvicorn>=0.27,<1.0; opensearch-py>=2.4,<3; mlflow-skinny>=2.9,<3 (plus pydantic, pydantic-settings, httpx already used by the project). Streamlit and pandas for page 6.
