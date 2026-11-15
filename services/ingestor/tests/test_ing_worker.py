"""Ingestor tests: template, group, idempotency, DLQ, retries, ack-after-index, files, health, speed."""
import json
import threading
import time
import urllib.request
from datetime import datetime, timezone

import pytest

from generator.core import GenConfig, build_events, to_line
from hc_common.constants import GROUP_INGESTORS, STREAM_DLQ, STREAM_TELEMETRY
from hc_common.schemas import Event
from ing_fakes import FakeOpenSearch, FakeRedis
from ingestor.health import start_health_server
from ingestor.template import TEMPLATE_NAME, build_template
from ingestor.worker import Ingestor, prepare

NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def lines():
    events, _ = build_events(GenConfig(profile="eval", scenarios=["phishing"], duration_hours=12,
                                       events_per_host_hour=60))
    return [to_line(e) for e in events]


def make(lines_=(), **kw):
    r, o = FakeRedis(), FakeOpenSearch()
    ing = Ingestor(r, o, clock=lambda: NOW, **kw)
    ing.ensure_ready()
    for line in lines_:
        r.xadd(STREAM_TELEMETRY, {"data": line})
    return ing, r, o


def drain(ing, limit=1000):
    total = 0
    for _ in range(limit):
        n = ing.run_once()
        total += n
        if n == 0:
            break
    return total


def test_template_matches_appendix_f():
    body = build_template()
    assert body["index_patterns"] == ["hc-events-*"]
    s = body["template"]
    assert s["settings"] == {"number_of_shards": 1, "number_of_replicas": 0}
    m = s["mappings"]
    assert m["dynamic"] == "false"
    p = m["properties"]
    assert p["host_ip"] == {"type": "ip"} and p["net"]["properties"]["src_ip"] == {"type": "ip"}
    assert p["auth"]["properties"]["src_ip"] == {"type": "keyword"}
    assert p["process"]["properties"]["cmdline"] == {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 512}}}
    assert p["file"]["properties"]["path"] == {"type": "keyword", "fields": {"text": {"type": "text"}}}
    assert p["gt"]["properties"]["is_malicious"] == {"type": "boolean"}
    assert p["net"]["properties"]["bytes_out"] == {"type": "long"}
    assert build_template("x-events")["index_patterns"] == ["x-events-*"]


def test_ensure_ready_creates_template_and_group_once():
    ing, r, o = make()
    assert TEMPLATE_NAME == "hc-events-template" and TEMPLATE_NAME in o.indices.templates
    assert GROUP_INGESTORS in r.groups[STREAM_TELEMETRY]
    ing.ensure_ready()  # BUSYGROUP must be tolerated


def test_indexes_all_and_acks_after_success(lines):
    ing, r, o = make(lines[:300], batch_size=100)
    assert drain(ing) == 300
    assert len(o.docs) == 300 and ing.stats.indexed == 300 and not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)
    idx, _ = next(iter(o.docs))
    assert idx.startswith("hc-events-2026.11.12")
    doc = next(iter(o.docs.values()))
    assert doc["ingested_at"] == "2026-11-13T12:00:00Z" and "gt" in doc
    assert not any(v is None for v in doc.values())


def test_daily_index_by_event_timestamp():
    ing, r, o = make()
    events, _ = build_events(GenConfig(profile="benign_train", duration_hours=26, events_per_host_hour=20))
    for e in events:
        r.xadd(STREAM_TELEMETRY, {"data": to_line(e)})
    drain(ing)
    assert {i for i, _ in o.docs} == {"hc-events-2026.11.11", "hc-events-2026.11.12"}


def test_reingest_is_idempotent(lines):
    ing, r, o = make(lines[:200])
    drain(ing)
    for line in lines[:200]:
        r.xadd(STREAM_TELEMETRY, {"data": line})
    drain(ing)
    assert len(o.docs) == 200 and ing.stats.indexed == 400


def test_poison_messages_go_to_dlq_and_do_not_stop_ingest(lines):
    ing, r, o = make()
    r.xadd(STREAM_TELEMETRY, {"data": "{not json"})
    r.xadd(STREAM_TELEMETRY, {"data": json.dumps({"event_id": "x"})})
    r.xadd(STREAM_TELEMETRY, {"other": "field"})
    bad_ip = json.loads(lines[0])
    bad_ip["host_ip"] = ""
    r.xadd(STREAM_TELEMETRY, {"data": json.dumps(bad_ip)})
    naive = json.loads(lines[1])
    naive["ts"] = "2026-11-12T09:00:00"
    r.xadd(STREAM_TELEMETRY, {"data": json.dumps(naive)})
    wrong = json.loads(lines[2])
    wrong["event_type"] = "auth"
    r.xadd(STREAM_TELEMETRY, {"data": json.dumps(wrong)})
    for line in lines[10:20]:
        r.xadd(STREAM_TELEMETRY, {"data": line})
    drain(ing)
    dlq = r.stream_fields(STREAM_DLQ)
    assert len(dlq) == 6 and len(o.docs) == 10 and ing.stats.dlq == 6
    assert all(set(f) == {"data", "error", "ts"} and f["error"] for f in dlq)
    assert dlq[0]["data"] == "{not json" and dlq[2]["data"] == ""
    assert not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_mapping_rejection_goes_to_dlq(lines):
    ing, r, o = make(lines[:5])
    victim = json.loads(lines[2])["event_id"]
    o.fail_ids[victim] = 400
    drain(ing)
    assert len(o.docs) == 4 and len(r.stream_fields(STREAM_DLQ)) == 1
    assert "400" in r.stream_fields(STREAM_DLQ)[0]["error"]
    assert not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_transient_item_failure_is_retried_not_acked(lines):
    ing, r, o = make(lines[:5])
    victim = json.loads(lines[1])["event_id"]
    o.fail_ids[victim] = 429
    assert ing.run_once() == 5
    assert len(o.docs) == 4 and len(r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)) == 1
    assert not r.stream_fields(STREAM_DLQ)
    del o.fail_ids[victim]
    drain(ing)
    assert len(o.docs) == 5 and not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_bulk_exception_leaves_messages_pending_and_recovers(lines):
    ing, r, o = make(lines[:50])
    o.raise_next = 1
    with pytest.raises(ConnectionError):
        ing.run_once()
    assert len(r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)) == 50 and not o.docs
    ing._read_pending = True
    drain(ing)
    assert len(o.docs) == 50 and not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_run_forever_survives_outage_with_backoff(lines):
    ing, r, o = make(lines[:30])
    o.raise_next = 2
    stop, naps = threading.Event(), []
    worker = threading.Thread(target=ing.run_forever, args=(stop, naps.append), daemon=True)
    worker.start()
    deadline = time.monotonic() + 10
    while len(o.docs) < 30 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    worker.join(5)
    assert len(o.docs) == 30 and naps[:2] == [0.5, 1.0] and not worker.is_alive()
    assert not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_restart_reprocesses_unacked_messages(lines):
    ing, r, o = make(lines[:20])
    r.xreadgroup(GROUP_INGESTORS, "ingestor-1", {STREAM_TELEMETRY: ">"}, count=20)  # delivered, never acked
    fresh = Ingestor(r, o, clock=lambda: NOW)
    fresh.ensure_ready()
    drain(fresh)
    assert len(o.docs) == 20 and not r.pending(STREAM_TELEMETRY, GROUP_INGESTORS)


def test_stale_messages_of_dead_consumer_are_claimed(lines):
    ing, r, o = make(lines[:10], consumer="ingestor-2")
    r.xreadgroup(GROUP_INGESTORS, "dead-consumer", {STREAM_TELEMETRY: ">"}, count=10)
    ing._read_pending = False
    drain(ing)
    assert len(o.docs) == 10


def test_trimmed_pending_entry_is_sent_to_dlq():
    ing, r, o = make()
    assert ing.process([("1-0", None)]) == ["1-0"]
    assert len(r.stream_fields(STREAM_DLQ)) == 1


def test_prepare_contract():
    ok, err = prepare(None, NOW)
    assert ok is None and err
    events, _ = build_events(GenConfig(profile="benign_train", duration_hours=1, events_per_host_hour=20))
    (index, event_id, doc), err = prepare(to_line(events[0]), NOW)
    assert err is None and event_id == events[0]["event_id"] and index == "hc-events-2026.11.11"
    Event.model_validate(doc)


def test_ingest_lines_file_path_idempotent(lines):
    ing, r, o = make()
    s1 = ing.ingest_lines(lines + ["", "garbage"], batch_size=250)
    s2 = ing.ingest_lines(lines)
    assert s1 == {"indexed": len(lines), "invalid": 1, "rejected": 0} and s2["indexed"] == len(lines)
    assert len(o.docs) == len(lines)


def test_health_server_reports_status_codes():
    state = {"status": "ok", "indexed": 3}
    server = start_health_server(lambda: dict(state), port=0, host="127.0.0.1")
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/health", timeout=5) as resp:
            body = json.loads(resp.read())
        assert resp.status == 200 and body["service"] == "ingestor" and body["indexed"] == 3
        state["status"] = "failed"
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + "/health", timeout=5)
        assert exc.value.code == 503
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + "/nope", timeout=5)
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_processing_speed_at_least_800_events_per_second():
    events, _ = build_events(GenConfig(profile="benign_train", duration_hours=12, events_per_host_hour=200))
    batch = [to_line(e) for e in events[:20000]]
    ing, r, o = make(batch, batch_size=500)
    t = time.monotonic()
    drain(ing)
    rate = len(batch) / (time.monotonic() - t)
    assert len(o.docs) == len(batch) and rate >= 800, rate
