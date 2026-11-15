"""REST contract tests for the ml service using a fake OpenSearch client (no network)."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import ml_main  # noqa: E402
import synth  # noqa: E402
from hc_common.config import get_settings  # noqa: E402


class FakeOS:
    """Returns stored events for any search; records the bodies it received."""

    def __init__(self, events):
        self.events = events
        self.bodies = []

    def ping(self):
        return True

    def search(self, index, body, **kw):
        self.bodies.append(body)
        if "aggs" in body:
            train = [e for e in self.events if "train" in e["tags"]]
            ts = sorted(e["ts"] for e in train)
            if not ts:
                return {"aggregations": {"lo": {"value": None}, "hi": {"value": None}}}
            return {"aggregations": {"lo": {"value": 1.7e12}, "hi": {"value": 1.7e12 + 1}}}
        if "search_after" in body:
            return {"hits": {"hits": []}}
        flt = body["query"]["bool"]["filter"]
        want_train = {"term": {"tags": "train"}} in flt
        hosts = next((f["terms"]["host"] for f in flt if "terms" in f), None)
        rows = [e for e in self.events if (("train" in e["tags"]) == want_train)
                and (hosts is None or e["host"] in hosts)]
        return {"hits": {"hits": [{"_source": e, "sort": [i]} for i, e in enumerate(rows)]}}


def setup(tmp_path, monkeypatch, events):
    monkeypatch.setenv("HC_MODEL_DIR", str(tmp_path))
    get_settings.cache_clear()
    monkeypatch.setattr(ml_main, "log_run", lambda *a, **k: True)
    ml_main._state["model"] = None
    ml_main._state["client"] = FakeOS(events)
    return TestClient(ml_main.app, raise_server_exceptions=False)


RANGE = {"start": "2026-11-12T00:00:00Z", "end": "2026-11-13T00:00:00Z"}


def test_health_without_model(tmp_path, monkeypatch):
    c = setup(tmp_path, monkeypatch, [])
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["model"] == "none"


def test_no_model_gives_409_conflict_and_404_for_meta(tmp_path, monkeypatch):
    c = setup(tmp_path, monkeypatch, [])
    r = c.post("/v1/windows", json={"time_range": RANGE})
    assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"
    assert c.get("/v1/models/current").status_code == 404


def test_invalid_range_and_body_use_error_format(tmp_path, monkeypatch):
    c = setup(tmp_path, monkeypatch, [])
    bad = {"start": "2026-11-13T00:00:00Z", "end": "2026-11-12T00:00:00Z"}
    r = c.post("/v1/windows", json={"time_range": bad})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"
    r = c.post("/v1/windows", json={"nope": 1})
    assert r.status_code == 422 and set(r.json()["error"]) == {"code", "message", "details"}


def test_train_windows_confidence_evaluate_flow(tmp_path, monkeypatch):
    events = synth.make_train(1001, 0.4) + synth.make_eval(2002, 0.4)
    c = setup(tmp_path, monkeypatch, events)
    r = c.post("/v1/train", json={"seed": 1001})
    assert r.status_code == 200
    body = r.json()
    assert len(body["model_id"]) == 32 and body["trained_at"].endswith("Z") and "n_windows" in body["metrics"]
    meta = c.get("/v1/models/current").json()
    assert meta["model_id"] == body["model_id"] and len(meta["feature_names"]) == 22
    assert (tmp_path / "current" / "meta.json").exists()

    w = c.post("/v1/windows", json={"time_range": RANGE, "hosts": ["WS-03"], "run_id": "r1"})
    assert w.status_code == 200
    items = w.json()["items"]
    assert items and w.json()["total"] == len(items) and {i["host"] for i in items} == {"WS-03"}
    top = max(items, key=lambda i: i["anomaly"])

    conf = c.post("/v1/confidence", json={"window": top, "stages_found": ["execution"],
                                          "expected_stages": ["execution", "lateral_movement"],
                                          "hosts": ["WS-03", "DB-01"]})
    assert conf.status_code == 200
    j = conf.json()
    assert set(j["scores"]) == {"anomaly_if", "anomaly_seq", "anomaly", "coverage", "criticality", "uncertainty",
                                "confidence"}
    assert j["scores"]["coverage"] == 0.5 and j["rationale"].startswith("Confidence ")

    ev = c.post("/v1/evaluate", json={"time_range": RANGE})
    assert ev.status_code == 200
    assert {"precision", "recall", "f1", "pr_auc", "false_positives_per_host_day"} <= set(ev.json())


def test_windows_request_never_asks_for_ground_truth(tmp_path, monkeypatch):
    events = synth.make_train(1001, 0.4) + synth.make_eval(2002, 0.4)
    c = setup(tmp_path, monkeypatch, events)
    c.post("/v1/train", json={})
    c.post("/v1/windows", json={"time_range": RANGE})
    client = ml_main._state["client"]
    scoring = [b for b in client.bodies if "aggs" not in b][-1]
    assert not any(f == "gt" or f.startswith("gt") for f in scoring["_source"])


def test_train_without_train_events_is_conflict(tmp_path, monkeypatch):
    c = setup(tmp_path, monkeypatch, synth.make_eval(2002, 0.3))
    r = c.post("/v1/train", json={})
    assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"
