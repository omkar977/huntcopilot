"""HuntCopilot ml service (port 8100). Spec Section 6.2. Run: python -m ml_main  (PYTHONPATH includes services/ml)."""
from __future__ import annotations

import os
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from hc_common.clients import get_opensearch
from hc_common.config import get_settings
from hc_common.logging import get_logger
from hc_common.schemas import ScoreBreakdown, ScoredWindow, TimeRange
from hc_ml import THRESHOLD, __version__
from hc_ml.confidence import compute_confidence
from hc_ml.evaluate import evaluate_windows
from hc_ml.jsonl import write_json
from hc_ml.model import AnomalyModel, NoTrainingData
from ml_tracking import log_run

import ml_store as store

log = get_logger("ml")
app = FastAPI(title="HuntCopilot ml", version=__version__)
_lock = threading.Lock()
_state: dict[str, Any] = {"model": None, "client": None}


class ApiError(Exception):
    """Error with the contract body {error: {code, message, details}}."""

    def __init__(self, status: int, code: str, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or {}


@app.exception_handler(ApiError)
async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
    body = {"error": {"code": exc.code, "message": exc.message, "details": exc.details}}
    return JSONResponse(status_code=exc.status, content=body)


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = {"errors": [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]}
    return JSONResponse(status_code=422, content={"error": {"code": "invalid_request",
                                                            "message": "request body is invalid", "details": details}})


@app.exception_handler(Exception)
async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error", extra={"error": type(exc).__name__})
    return JSONResponse(status_code=500, content={"error": {"code": "internal", "message": "internal error",
                                                            "details": {}}})


class TrainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = 1001
    time_range: Optional[TimeRange] = None


class WindowsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time_range: TimeRange
    hosts: Optional[list[str]] = None
    run_id: Optional[str] = None


class ConfidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    window: ScoredWindow
    stages_found: list[str] = Field(default_factory=list)
    expected_stages: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time_range: TimeRange


def _client() -> Any:
    if _state["client"] is None:
        _state["client"] = get_opensearch()
    return _state["client"]


def _events_index() -> str:
    return get_settings().hc_events_index_prefix + "-*"


def _check_range(tr: TimeRange) -> None:
    if tr.end <= tr.start:
        raise ApiError(422, "invalid_request", "time_range.end must be after time_range.start")


def current_model() -> AnomalyModel:
    """Return the loaded model, loading it from HC_MODEL_DIR/current on first use. 409 if none exists."""
    with _lock:
        if _state["model"] is None:
            try:
                _state["model"] = AnomalyModel.load(get_settings().hc_model_dir)
            except FileNotFoundError:
                raise ApiError(409, "conflict", "no trained model; call POST /v1/train first") from None
        return _state["model"]


def _fetch(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - map any store failure to one clean error
        log.error("opensearch read failed", extra={"error": type(exc).__name__})
        raise ApiError(503, "internal", "events store unavailable", {"reason": type(exc).__name__}) from exc


@app.get("/health")
def health() -> dict:
    """Liveness plus model and OpenSearch state."""
    try:
        os_state = "up" if _client().ping() else "down"
    except Exception:  # noqa: BLE001
        os_state = "down"
    model_loaded = _state["model"] is not None or os.path.exists(
        os.path.join(get_settings().hc_model_dir, "current", "meta.json"))
    return {"status": "ok", "version": __version__, "model": "loaded" if model_loaded else "none",
            "opensearch": os_state}


@app.post("/v1/train")
def train(req: Optional[TrainRequest] = None) -> dict:
    """Train on events tagged train and save the model under HC_MODEL_DIR/current."""
    req = req or TrainRequest()
    s = get_settings()
    if req.time_range is not None:
        _check_range(req.time_range)
        start, end = req.time_range.start, req.time_range.end
    else:
        bounds = _fetch(store.time_bounds, _client(), _events_index(), True)
        if bounds is None:
            raise ApiError(409, "conflict", "no events tagged train in the events index")
        start, end = bounds
    events = _fetch(store.fetch_events, _client(), _events_index(), start, end, None, True)
    try:
        model = AnomalyModel.train(events, seed=req.seed, per_group=os.getenv("HC_ML_PER_GROUP", "1") != "0",
                                   per_host_rare=os.getenv("HC_ML_PER_HOST_RARE", "1") != "0",
                                   beacon_min_net=int(os.getenv("HC_ML_BEACON_MIN_NET", "0")))
    except NoTrainingData as exc:
        raise ApiError(409, "conflict", str(exc)) from exc
    model.save(s.hc_model_dir)
    with _lock:
        _state["model"] = model
    meta = model.public_meta()
    _log_train(model, s.hc_model_dir)
    return {"model_id": meta["model_id"], "trained_at": meta["trained_at"], "metrics": meta["train_metrics"]}


def _log_train(model: AnomalyModel, model_dir: str) -> None:
    meta_file = os.path.join(model_dir, "current", "meta.json")
    log_run("train", {"seed": model.meta["seed"], "n_models": 5, "n_estimators": 200,
                      "model_id": model.meta["model_id"]},
            model.meta.get("train_metrics", {}), {"meta": meta_file})


@app.post("/v1/windows")
def windows(req: WindowsRequest) -> dict:
    """Score 15-minute host windows in the time range with the current model."""
    _check_range(req.time_range)
    model = current_model()
    events = _fetch(store.fetch_events, _client(), _events_index(), req.time_range.start, req.time_range.end,
                    req.hosts)
    items = model.score_events(events, req.hosts)
    valid = [ScoredWindow(**w).model_dump(mode="json") for w in items]
    return {"items": valid, "total": len(valid)}


@app.post("/v1/confidence")
def confidence(req: ConfidenceRequest) -> dict:
    """Confidence score, its components and the deterministic rationale."""
    window = req.window.model_dump(mode="json")
    scores, rationale = compute_confidence(window, req.stages_found, req.expected_stages, req.hosts)
    return {"scores": ScoreBreakdown(**scores).model_dump(mode="json"), "rationale": rationale}


@app.post("/v1/evaluate")
def evaluate(req: EvaluateRequest) -> dict:
    """Evaluate against ground truth (the only endpoint that reads labels) and log to MLflow."""
    _check_range(req.time_range)
    model = current_model()
    events = _fetch(store.fetch_labelled_events, _client(), _events_index(), req.time_range.start,
                    req.time_range.end)
    if not events:
        raise ApiError(409, "conflict", "no events in the requested time range")
    result = evaluate_windows(model.score_events(events), events, THRESHOLD)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "evaluation.json")
        write_json(path, result)
        log_run("evaluate", {"model_id": model.meta["model_id"], "threshold": THRESHOLD}, result, {"report": path})
    return {**result, "model_id": model.meta["model_id"],
            "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


@app.get("/v1/models/current")
def models_current() -> dict:
    """Metadata of the current model (404 when none)."""
    try:
        model = current_model()
    except ApiError:
        raise ApiError(404, "not_found", "no trained model") from None
    out = model.public_meta()
    out["feature_baseline"] = model.feature_baseline()
    return out


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8100, log_level=get_settings().hc_log_level.lower())
