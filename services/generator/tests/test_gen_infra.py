"""Redis sink, runner, control API (port 8300) and CLI tests. No network and no Redis needed."""
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from gen_fake_redis import FakeRedis
from generator import cli
from generator.api import create_server
from generator.core import GenConfig, build_events
from generator.runner import Busy, Runner
from generator.sinks import BACKLOG_LIMIT, push_redis, wait_for_capacity, write_jsonl
from hc_common.constants import STREAM_MAXLEN, STREAM_TELEMETRY
from hc_common.schemas import Event

SMALL = dict(profile="eval", scenarios=["phishing"], duration_hours=12, events_per_host_hour=60)
KEY = "unit-test-key"


@pytest.fixture(scope="module")
def small_events():
    return build_events(GenConfig(**SMALL))[0]


def test_push_redis_burst(small_events):
    r, seen = FakeRedis(), []
    n = push_redis(small_events, r, "burst", progress=seen.append)
    assert n == len(small_events) == len(r.streams[STREAM_TELEMETRY])
    assert seen[-1] == n and seen == sorted(seen)
    assert all(c == (STREAM_MAXLEN, True) for c in r.calls)
    first = json.loads(r.streams[STREAM_TELEMETRY][0]["data"])
    Event.model_validate(first)
    assert set(r.streams[STREAM_TELEMETRY][0]) == {"data"}


def test_push_redis_realtime_paces_by_time_scale(small_events):
    from datetime import datetime

    slept, now = [], [0.0]

    def fake_sleep(s):
        slept.append(s)
        now[0] += s

    chunk = small_events[:400]
    push_redis(chunk, FakeRedis(), "realtime", time_scale=3600, sleep=fake_sleep, clock=lambda: now[0])

    def t(e):
        return datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))

    last_batch_start = chunk[(len(chunk) - 1) // 50 * 50]
    expected = (t(last_batch_start) - t(chunk[0])).total_seconds() / 3600
    assert slept and all(s > 0 for s in slept)
    assert sum(slept) == pytest.approx(expected, rel=1e-6)


def test_backpressure_waits_then_fails():
    r = FakeRedis(backlog=BACKLOG_LIMIT + 1)
    naps = []
    with pytest.raises(RuntimeError, match="ingestor"):
        wait_for_capacity(r, sleep=naps.append, max_wait_s=2)
    assert len(naps) == 4


def test_write_jsonl_roundtrip(tmp_path, small_events):
    path = tmp_path / "sub" / "events.jsonl"
    assert write_jsonl(small_events, str(path)) == len(small_events)
    lines = path.read_text().splitlines()
    assert len(lines) == len(small_events) and Event.model_validate_json(lines[0])


def test_runner_lifecycle(tmp_path):
    r = FakeRedis()
    runner = Runner(redis_factory=lambda: r, labels_path=lambda: str(tmp_path / "labels.json"))
    assert runner.status()["state"] == "idle"
    run_id = runner.start(GenConfig(**SMALL))
    runner.wait(30)
    st = runner.status()
    assert st["state"] == "done" and st["run_id"] == run_id and st["produced"] == st["total"] > 0 and not st["error"]
    assert len(r.streams[STREAM_TELEMETRY]) == st["produced"]
    labels = json.loads((tmp_path / "labels.json").read_text())
    assert labels["run_id"] == run_id and "phishing" in labels["scenarios"]


def test_runner_busy_and_errors(tmp_path):
    gate = threading.Event()
    runner = Runner(redis_factory=lambda: FakeRedis(), labels_path=lambda: str(tmp_path / "l.json"),
                    sleep=lambda s: gate.wait(5))
    runner.start(GenConfig(**SMALL), speed="realtime", time_scale=0.001)
    time.sleep(0.2)
    with pytest.raises(Busy):
        runner.start(GenConfig(**SMALL))
    gate.set()
    runner.wait(30)
    with pytest.raises(ValueError):
        runner.start(GenConfig(**SMALL), speed="warp")
    broken = Runner(redis_factory=None, labels_path=lambda: str(tmp_path / "l2.json"))
    broken.start(GenConfig(**SMALL))
    broken.wait(30)
    assert broken.status()["state"] == "done" and "redis" in broken.status()["error"]


# ----------------------------------------------------------------- control API
@pytest.fixture()
def api(tmp_path):
    fake = FakeRedis()
    runner = Runner(redis_factory=lambda: fake, labels_path=lambda: str(tmp_path / "labels.json"))
    server = create_server(runner, KEY, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield base, runner, fake
    server.shutdown()
    server.server_close()


def call(base, path, method="GET", body=None, key=KEY):
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-API-Key"] = key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_api_health_needs_no_key(api):
    code, body = call(api[0], "/health", key=None)
    assert code == 200 and body["status"] == "ok"


def test_api_requires_key(api):
    for path in ("/v1/scenarios", "/v1/status"):
        code, body = call(api[0], path, key="wrong")
        assert code == 401 and body["error"]["code"] == "invalid_request"
    assert call(api[0], "/v1/run", "POST", {}, key=None)[0] == 401


def test_api_scenarios_and_status(api):
    code, body = call(api[0], "/v1/scenarios")
    assert code == 200 and body["items"] == ["phishing", "lateral_movement", "credential_dumping", "c2", "apt_chain"]
    assert body["total"] == 5
    code, body = call(api[0], "/v1/status")
    assert code == 200 and body["state"] == "idle" and body["produced"] == 0 and body["run_id"] == ""


def test_api_run_to_done(api):
    base, runner, fake = api
    code, body = call(base, "/v1/run", "POST", {"profile": "eval", "scenarios": ["phishing"], "seed": 5,
                                                "duration_hours": 12, "events_per_host_hour": 60, "speed": "burst"})
    assert code == 202 and len(body["run_id"]) == 32
    runner.wait(30)
    code, st = call(base, "/v1/status")
    assert st["state"] == "done" and st["run_id"] == body["run_id"] and st["produced"] > 0
    assert len(fake.streams[STREAM_TELEMETRY]) == st["produced"]


def test_api_conflict_when_running(api):
    base, runner, _ = api
    gate = threading.Event()
    runner._sleep = lambda s: gate.wait(5)
    body = {"profile": "eval", "scenarios": ["phishing"], "duration_hours": 12, "events_per_host_hour": 60,
            "speed": "realtime", "time_scale": 0.001}
    assert call(base, "/v1/run", "POST", body)[0] == 202
    time.sleep(0.2)
    code, err = call(base, "/v1/run", "POST", body)
    assert code == 409 and err["error"]["code"] == "conflict"
    gate.set()
    runner.wait(30)


@pytest.mark.parametrize("body", [
    {"profile": "nope"}, {"profile": "benign_train", "scenarios": ["c2"]}, {"scenarios": ["x"]},
    {"duration_hours": -1}, {"speed": "warp"}, {"surprise": 1}, {"scenarios": "c2"}, {"seed": "abc"},
])
def test_api_rejects_bad_bodies(api, body):
    code, err = call(api[0], "/v1/run", "POST", body)
    assert code == 400 and err["error"]["code"] == "invalid_request" and "message" in err["error"]


def test_api_unknown_route(api):
    assert call(api[0], "/v1/nothing")[0] == 404
    assert call(api[0], "/v1/nothing", "POST", {})[0] == 404


# ----------------------------------------------------------------- CLI
def test_cli_jsonl_run(tmp_path, capsys):
    out = tmp_path / "events.jsonl"
    code = cli.main(["run", "--profile", "eval", "--scenarios", "phishing", "c2", "--seed", "2002",
                     "--duration-hours", "12", "--events-per-host-hour", "60", "--out", "jsonl",
                     "--jsonl-path", str(out)])
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["events"] == len(out.read_text().splitlines())
    labels = json.loads((tmp_path / "labels.json").read_text())
    assert set(labels["scenarios"]) == {"phishing", "c2"}


def test_cli_comma_scenarios_and_bad_input(tmp_path, capsys):
    out = tmp_path / "e.jsonl"
    assert cli.main(["run", "--scenarios", "phishing,c2", "--duration-hours", "12", "--events-per-host-hour", "40",
                     "--out", "jsonl", "--jsonl-path", str(out)]) == 0
    assert cli.main(["run", "--profile", "benign_train", "--scenarios", "c2", "--out", "jsonl",
                     "--jsonl-path", str(out)]) == 2
    assert "benign_train" in capsys.readouterr().err
    assert cli.main(["scenarios"]) == 0


def test_cli_benign_train_default_seed(tmp_path):
    out = tmp_path / "train.jsonl"
    assert cli.main(["run", "--profile", "benign_train", "--duration-hours", "2", "--out", "jsonl",
                     "--jsonl-path", str(out)]) == 0
    first = json.loads(out.read_text().splitlines()[0])
    assert first["tags"] == ["train"] and first["ts"].startswith("2026-11-11")
