# ml service (M3)

REST service on port 8100 (spec Section 6.2). Logic lives in `libs/hc_ml`.

Run locally (from the repo root, with `pip install -r services/ml/requirements.txt`):

    export HC_OPENSEARCH_URL=http://localhost:9200 HC_MODEL_DIR=/tmp/models HC_MLFLOW_URI=file:///tmp/mlruns
    PYTHONPATH=common:libs:services/ml python -m ml_main

Docker (Appendix G pattern): `MODULE=ml_main`, `PORT=8100`, `PYTHONPATH=/app/common:/app/libs:/app/services/ml`.

Endpoints: `GET /health`, `POST /v1/train`, `POST /v1/windows`, `POST /v1/confidence`, `POST /v1/evaluate`,
`GET /v1/models/current`. Errors use `{"error": {"code", "message", "details"}}`.

Files: `ml_main.py` (app), `ml_store.py` (read-only OpenSearch queries), `ml_tracking.py` (optional MLflow).

Train and evaluate without OpenSearch:

    PYTHONPATH=common:libs python -m hc_ml train --events data/train.jsonl --force-train-tag --model-dir /tmp/models
    PYTHONPATH=common:libs python -m hc_ml evaluate --events data/eval.jsonl --model-dir /tmp/models
