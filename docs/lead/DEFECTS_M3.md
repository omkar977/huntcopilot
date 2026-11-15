# M3: verdict ACCEPT WITH FIXES (zip v1). Due: v2 Sun 15 Nov 18:00

Lead ran here (real pytest, real ruff, M1 data): `PYTHONPATH=common:libs:services/ml pytest -q libs/hc_ml services/ml` = 41 passed, 1 skipped (test_svc_api.py: fastapi not installed here). Ruff clean. Checker PASS. File name had a `_1` suffix: use exactly HC_M3_ml_v2_YYYYMMDD-HHMM.zip.

## Real results on M1 generator data (train seed 1001, eval seed 2002)
Command: `python -m hc_ml train --events data/train.jsonl --model-dir M --seed 1001` then `evaluate --events data/eval.jsonl`.

| Metric | Target (spec 1.7) | Got |
|---|---|---|
| Precision | >= 0.60 | 0.237 (tp 14, fp 45, fn 9) |
| Recall | >= 0.85 | 0.609 |
| False positives per host-day | <= 3 | 3.75 |
| PR-AUC | - | 0.216 |
| Train 49,217 events | - | 3.6 s |

## Defects
1. [M3, MUST] Tune on the real data (the data above is in the shared zip). Diagnosis by Lead:
   - 36 of 45 false positives are on servers: FILE-01 16, WEB-01 11, DB-01 7, DC-01 4. Top features on FP windows: rare_process_score, rare_parent_child_score, beacon_cv. Servers have a different benign baseline than the 7 workstations, and one global model treats them as outliers.
   - Missed windows (9) are mostly DB-01 with anomaly 0.24 to 0.5 (just under the 0.5 threshold).
   - Ideas to try (spec 9.2 allows tuning but not new contracts): per-role baselines (server vs workstation) for scaler, p50/p99 and z-scores; per-host rare_* tables; beacon_cv only when n_net is high enough. Keep it deterministic. Report before/after metrics on eval seed 2002 AND one more seed (generate with M1's CLI, `--seed 3003`). Do not tune on seed 2002 alone.
2. [M3] Run `test_svc_api.py` for real (needs fastapi, httpx). Paste the last lines.
3. [M3] Spec 6: every endpoint except /health needs X-API-Key. Your service has none. Lead decision: ACCEPT (internal service, port on 127.0.0.1) and spec is updated. No action, but the dashboard page 6 must not send secrets to it.
4. [Lead, done] Dockerfile.ml start command changed to `uvicorn ml_main:app` (your ml_main). Confirm your service starts with `python -m uvicorn ml_main:app --port 8100` from `services/ml` with PYTHONPATH=common:libs:services/ml.
5. [M3] Page 6 calls the ml service with its own helper (accepted). Make sure every error shows st.error and never a traceback. Run it with `streamlit run` and send a screenshot, or say it was not run.
6. [M3] Validate service responses against hc_common.schemas (ScoredWindow, ScoreBreakdown): add a test that builds the models from your JSON output. pydantic validation was listed as not verified.
7. [M3] mlflow: run once with real mlflow-skinny; say whether logging worked.
