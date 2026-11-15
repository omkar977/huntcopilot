"""Sanity tests for the shared fixtures (standard library only)."""
import json
import os
from pathlib import Path

FIX = Path(os.getenv("HC_FIXTURES", Path(__file__).parent / "fixtures"))


def load():
    return [json.loads(line) for line in (FIX / "events_sample.jsonl").read_text(encoding="utf-8").splitlines()]


def test_size_and_order():
    ev = load()
    assert 250 <= len(ev) <= 350
    keys = [(e["ts"], e["event_id"]) for e in ev]
    assert keys == sorted(keys)
    assert len({e["event_id"] for e in ev}) == len(ev)


def test_exactly_one_payload_matches_type():
    mapping = {"process_create": "process", "network_conn": "net", "auth": "auth", "file_create": "file", "dns_query": "dns"}
    for e in load():
        present = [n for n in mapping.values() if e.get(n) is not None]
        assert present == [mapping[e["event_type"]]]


def test_ground_truth_present():
    ev = load()
    assert all("gt" in e for e in ev)
    malicious = [e for e in ev if e["gt"]["is_malicious"]]
    assert 20 <= len(malicious) <= 80


def test_expected_alerts_file():
    exp = json.loads((FIX / "expected_alerts.json").read_text(encoding="utf-8"))
    assert {"must_fire", "must_not_fire"} <= set(exp)
    assert any(x["rule_id"] == "HC-007" for x in exp["must_fire"])


def test_assets_file():
    assets = json.loads((FIX / "assets.json").read_text(encoding="utf-8"))
    assert len(assets) == 12
    assert {a["host"] for a in assets} >= {"DC-01", "DB-01", "FILE-01", "WEB-01", "WS-01", "WS-08"}
