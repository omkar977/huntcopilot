"""Contract tests: every fixture event must validate, and bad shapes must be rejected."""
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

pydantic = pytest.importorskip("pydantic")
from hc_common.schemas import Alert, Event, EventType  # noqa: E402

FIX = Path(os.getenv("HC_FIXTURES", Path(__file__).parent / "fixtures"))


def test_all_fixture_events_validate():
    for line in (FIX / "events_sample.jsonl").read_text(encoding="utf-8").splitlines():
        ev = Event.model_validate_json(line)
        assert ev.ts.tzinfo is not None


def test_payload_must_match_type():
    base = {"event_id": "x", "ts": "2026-11-12T09:30:00Z", "host": "WS-01", "host_ip": "10.10.1.11"}
    with pytest.raises(pydantic.ValidationError):
        Event.model_validate({**base, "event_type": "process_create"})  # no process payload
    with pytest.raises(pydantic.ValidationError):
        Event.model_validate({**base, "event_type": "dns_query", "dns": {"query": "a.test"},
                              "net": {"src_ip": "10.10.1.11", "dst_ip": "10.10.1.12", "dst_port": 80}})


def test_naive_timestamp_rejected():
    with pytest.raises(pydantic.ValidationError):
        Event.model_validate({"event_id": "x", "ts": "2026-11-12T09:30:00", "host": "WS-01", "host_ip": "10.10.1.11",
                              "event_type": "dns_query", "dns": {"query": "a.test"}})


def test_unknown_field_rejected():
    with pytest.raises(pydantic.ValidationError):
        Event.model_validate({"event_id": "x", "ts": "2026-11-12T09:30:00Z", "host": "WS-01", "host_ip": "10.10.1.11",
                              "event_type": "dns_query", "dns": {"query": "a.test"}, "surprise": 1})


def test_process_names_are_lowercased():
    ev = Event.model_validate({"event_id": "x", "ts": "2026-11-12T09:30:00Z", "host": "WS-01", "host_ip": "10.10.1.11",
                               "event_type": "process_create",
                               "process": {"name": "PowerShell.EXE", "pid": 1, "parent_name": "WINWORD.EXE"}})
    assert ev.process.name == "powershell.exe" and ev.process.parent_name == "winword.exe"
    assert ev.event_type is EventType.process_create


def test_alert_severity_range():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    ok = dict(alert_id="a", rule_id="HC-001", rule_name="n", severity=4, technique_ids=[], tactics=[], host="WS-03",
              ts_first=now, ts_last=now, event_ids=["e"], summary="s", created_at=now)
    Alert(**ok)
    with pytest.raises(pydantic.ValidationError):
        Alert(**{**ok, "severity": 9})
