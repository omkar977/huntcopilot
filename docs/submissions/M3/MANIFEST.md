# MANIFEST
Module: ml (libs/hc_ml, services/ml, dashboard page 6)   Member: M3   Version: v1   Date: 2026-11-14

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
I ran the library tests (34) and store tests (7) with a small stand-in runner: 41 passed, 0 failed (see pytest_output.txt).
NOT executed anywhere yet: services/ml/tests/test_svc_api.py, ml_main.py itself, page 6, and ruff. Please run the command above first.

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
10. meta.json also holds the training statistics (process frequencies, known domains, feature means and stds). model_id is a uuid4 hex.
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
