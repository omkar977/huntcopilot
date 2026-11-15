"""Detector service tests with a fake OpenSearch and Redis, plus the HTTP API on localhost. Owner: M2."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import detector_service as ds
from hc_detect.loader import load_rules
from hc_detect.tests.helpers import load_sample, proc
from hc_detect.timeutil import parse_ts


class FakeIndices:
    def __init__(self):
        self.created = []

    def exists(self, index):
        return bool(self.created)

    def create(self, index, body):
        self.created.append((index, body))


class FakeOpenSearch:
    def __init__(self, events):
        self.events = sorted(events, key=lambda e: (e["ts"], e["event_id"]))
        self.docs = {}
        self.indices = FakeIndices()
        self.bodies = []

    def search(self, index, body):
        self.bodies.append(body)
        if "match_all" in body["query"]:
            hits = [{"_source": {"ts": self.events[-1]["ts"]}}] if self.events else []
            return {"hits": {"hits": hits}}
        rng = body["query"]["bool"]["filter"][0]["range"]["ts"]
        rows = [e for e in self.events if rng["gte"] <= e["ts"] <= rng["lte"]]
        if "search_after" in body:
            key = body["search_after"]
            rows = [e for e in rows if (e["ts"], e["event_id"]) > tuple(key)]
        rows = rows[: body["size"]]
        return {"hits": {"hits": [{"_source": e, "sort": [e["ts"], e["event_id"]]} for e in rows]}}

    def bulk(self, body, refresh=None):
        items = []
        for i in range(0, len(body), 2):
            _id, op = body[i]["update"]["_id"], body[i + 1]
            if _id in self.docs:
                self.docs[_id].update(op["doc"])
                items.append({"update": {"result": "updated"}})
            else:
                self.docs[_id] = dict(op["upsert"])
                items.append({"update": {"result": "created"}})
        return {"items": items}

    def ping(self):
        return True


class FakeRedis:
    def __init__(self):
        self.sent = []

    def xadd(self, stream, fields, maxlen=None, approximate=None):
        self.sent.append((stream, json.loads(fields["data"])))


def make(events=None):
    events = load_sample() if events is None else events
    client, redis = FakeOpenSearch(events), FakeRedis()
    return ds.Detector(load_rules(), client, redis), client, redis


RANGE = (parse_ts("2026-11-12T09:00:00Z"), parse_ts("2026-11-12T11:00:00Z"))


def test_run_batch_creates_alerts_counts_and_publishes():
    det, client, redis = make()
    result = det.run_batch(*RANGE)
    assert result["events_evaluated"] == 288 and result["alerts_created"] == result["alerts_total"] == len(client.docs)
    assert result["per_rule"]["HC-006"] == 4 and result["per_rule"]["HC-008"] == 0 and result["per_rule"]["HC-009"] == 0
    assert set(result["per_rule"]) == {f"HC-{i:03d}" for i in range(1, 11)}
    assert len(redis.sent) == result["alerts_created"] and redis.sent[0][0] == "hc:alerts"
    assert client.indices.created and client.indices.created[0][0] == "hc-alerts"


def test_run_batch_is_idempotent_and_keeps_status():
    det, client, redis = make()
    first = det.run_batch(*RANGE)
    some_id = next(iter(client.docs))
    client.docs[some_id]["status"] = "triaged"
    second = det.run_batch(*RANGE)
    assert second["alerts_created"] == 0 and second["alerts_total"] == first["alerts_total"]
    assert len(client.docs) == first["alerts_total"] and client.docs[some_id]["status"] == "triaged"
    assert len(redis.sent) == first["alerts_created"]


def test_fetch_never_asks_for_ground_truth_and_paginates(monkeypatch):
    monkeypatch.setattr(ds, "PAGE_SIZE", 50)
    det, client, _ = make()
    assert len(det.fetch_events(*RANGE)) == 288
    assert len(client.bodies) >= 6
    assert all(b["_source"] == {"excludes": ["gt"]} for b in client.bodies)


def test_follow_once_uses_newest_event_not_the_wall_clock():
    det, client, _ = make()
    result = det.follow_once()
    assert result["alerts_total"] > 0
    rng = client.bodies[-1]["query"]["bool"]["filter"][0]["range"]["ts"]
    assert rng["lte"] == client.events[-1]["ts"]
    assert parse_ts(rng["lte"]) - parse_ts(rng["gte"]) == ds.FOLLOW_WINDOW
    empty, _, _ = make(events=[])
    assert empty.follow_once() is None


def test_redis_failure_does_not_stop_detection():
    det, _, redis = make()

    def boom(*a, **k):
        raise ConnectionError("down")
    redis.xadd = boom
    assert det.run_batch(*RANGE)["alerts_created"] > 0
    nored = ds.Detector(load_rules(), FakeOpenSearch(load_sample()), None)
    assert nored.run_batch(*RANGE)["alerts_created"] > 0


def test_new_events_extend_existing_alert_without_new_creation():
    base = [proc(i * 10, "psexesvc.exe", host="DB-01", event_id=f"e{i}") for i in range(1)]
    det, client, _ = make(events=base)
    rng = (parse_ts("2026-11-12T09:00:00Z"), parse_ts("2026-11-12T11:00:00Z"))
    assert det.run_batch(*rng)["per_rule"]["HC-006"] == 1


def test_parse_batch_body_errors():
    for raw, status in [(b"nope", 400), (b"{}", 422), (b'{"start":"x","end":"y"}', 422),
                        (b'{"start":"2026-11-12T10:00:00Z","end":"2026-11-12T09:00:00Z"}', 422),
                        (b'{"start":"2026-11-12T09:00:00","end":"2026-11-12T10:00:00Z"}', 422)]:
        with pytest.raises(ds.RequestError) as info:
            ds.parse_batch_body(raw)
        assert info.value.status == status
    start, end = ds.parse_batch_body(b'{"start":"2026-11-12T09:00:00Z","end":"2026-11-12T10:00:00Z"}')
    assert end > start


@pytest.fixture()
def server():
    det, client, _ = make()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ds.make_handler(det, "test-key-value"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", client
    httpd.shutdown()
    httpd.server_close()


def call(url, method="GET", body=None, key="test-key-value"):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None)
    if key:
        req.add_header("X-API-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_http_health_needs_no_key_and_rules_lists_ten(server):
    base, _ = server
    status, body = call(base + "/health", key=None)
    assert status == 200 and body["status"] == "ok" and body["rules"] == 10
    status, body = call(base + "/v1/rules")
    assert status == 200 and body["total"] == 10
    assert set(body["items"][0]) == {"id", "name", "severity", "enabled"}


def test_http_requires_api_key(server):
    base, _ = server
    assert call(base + "/v1/rules", key=None)[0] == 401
    assert call(base + "/v1/rules", key="wrong")[0] == 401
    status, body = call(base + "/v1/run-batch", "POST", {"start": "a", "end": "b"}, key=None)
    assert status == 401 and body["error"]["code"] == "invalid_request"


def test_http_run_batch_and_errors(server):
    base, client = server
    status, body = call(base + "/v1/run-batch", "POST", {"start": "2026-11-12T09:00:00Z", "end": "2026-11-12T11:00:00Z"})
    assert status == 200 and body["alerts_created"] > 0 and body["per_rule"]["HC-001"] == 1
    assert len(client.docs) == body["alerts_total"]
    status, body = call(base + "/v1/run-batch", "POST", {"start": "bad", "end": "worse"})
    assert status == 422 and body["error"]["code"] == "validation_failed"
    assert call(base + "/v1/nothing")[0] == 404
    assert call(base + "/v1/nothing", "POST", {})[0] == 404
