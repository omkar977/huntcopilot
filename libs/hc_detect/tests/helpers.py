"""Event builders and fixture access shared by the hc_detect tests. Owner: M2."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

BASE = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)
_counter = {"n": 0}


def fixtures_dir() -> Path:
    env = os.getenv("HC_FIXTURES")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "tests" / "fixtures").is_dir():
            return parent / "tests" / "fixtures"
    raise FileNotFoundError("tests/fixtures not found")


def load_sample() -> List[dict]:
    path = fixtures_dir() / "events_sample.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def stamp(offset_s: float) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base(event_type: str, t: float, host: str, user: str, event_id: Optional[str]) -> dict:
    _counter["n"] += 1
    return {
        "schema_version": "1.0",
        "event_id": event_id or f"ev{_counter['n']:08d}",
        "ts": stamp(t),
        "host": host,
        "host_ip": "10.10.1.13",
        "user": user,
        "event_type": event_type,
        "process": None,
        "net": None,
        "auth": None,
        "file": None,
        "dns": None,
        "tags": [],
        "gt": {"is_malicious": False, "scenario": "", "stage": ""},
    }


def proc(t, name, cmdline="", parent="explorer.exe", host="WS-03", user="carol", event_id=None) -> dict:
    ev = _base("process_create", t, host, user, event_id)
    ev["process"] = {"name": name, "pid": 100, "cmdline": cmdline or name, "parent_name": parent,
                     "parent_pid": 50, "user": user, "integrity": "medium"}
    return ev


def net(t, dst_ip, port=443, direction="outbound", host="WS-03", user="carol", event_id=None, dst_host="") -> dict:
    ev = _base("network_conn", t, host, user, event_id)
    ev["net"] = {"src_ip": "10.10.1.13", "src_port": 50000, "dst_ip": dst_ip, "dst_port": port, "proto": "tcp",
                 "bytes_out": 300, "bytes_in": 0, "dst_host": dst_host, "direction": direction}
    return ev


def auth(t, host="DB-01", logon=3, result="success", src_host="WS-03", target="adm_it", event_id=None) -> dict:
    ev = _base("auth", t, host, target, event_id)
    ev["auth"] = {"logon_type": logon, "result": result, "target_user": target, "src_host": src_host, "src_ip": ""}
    return ev


def file_ev(t, path, host="WS-03", user="carol", event_id=None) -> dict:
    ev = _base("file_create", t, host, user, event_id)
    ev["file"] = {"path": path, "action": "create", "sha256": ""}
    return ev


def dns(t, query, host="WS-03", user="carol", event_id=None) -> dict:
    ev = _base("dns_query", t, host, user, event_id)
    ev["dns"] = {"query": query, "qtype": "A", "answer": "", "rcode": "NOERROR"}
    return ev
