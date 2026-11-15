"""Mocks that make the api independent of other modules (spec Section 12.4).

HC_MOCK_ML=1   -> MockMl: canned ScoredWindow and confidence responses.
HC_MOCK_HUNT=1 -> FixtureBackend (events and alerts from tests/fixtures) and mock_run_plan.
Both are switched off by simply not setting the variables.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from hc_common.clients import parse_ts
from hc_common.constants import CRITICALITY
from hc_common.ids import sha1_hex
from hc_common.schemas import (Alert, FeatureContribution, HuntPlan, ScoreBreakdown, ScoredWindow, StepResult,
                               TimeRange)

MAX_VAR_VALUES = 50
MAX_EVIDENCE = 500


def fixtures_dir() -> Path:
    """HC_FIXTURES if set, else tests/fixtures found by walking up from this file."""
    env = os.getenv("HC_FIXTURES")
    if env:
        return Path(env)
    for parent in Path(__file__).resolve().parents:
        cand = parent / "tests" / "fixtures"
        if cand.is_dir():
            return cand
    return Path("tests/fixtures")


def strip_truth(event: dict) -> dict:
    """Copy of the event without the evaluation-only label block."""
    return {k: v for k, v in event.items() if k != "gt"}


def load_fixture_events() -> list[dict]:
    path = fixtures_dir() / "events_sample.jsonl"
    with open(path, "r", encoding="utf-8") as fh:
        events = [strip_truth(json.loads(line)) for line in fh if line.strip()]
    return sorted(events, key=lambda e: (e["ts"], e["event_id"]))


# ---------------------------------------------------------------- in-memory run_plan
def _get(ev: dict, path: str) -> Any:
    cur: Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur or cur[part] is None:
            return None
        cur = cur[part]
    return cur


def _cmp(actual: Any, op: str, value: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_cmp(a, op, value) for a in actual)
    text = str(actual).lower()
    if op == "eq":
        return text == str(value).lower()
    if op == "neq":
        return text != str(value).lower()
    if op == "in":
        return text in {str(v).lower() for v in (value if isinstance(value, list) else [value])}
    if op == "contains":
        return str(value).lower() in text
    if op == "startswith":
        return text.startswith(str(value).lower())
    try:
        a, b = float(actual), float(value)
    except (TypeError, ValueError):
        a, b = str(actual), str(value)
    return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}.get(op, False)


def _derived(events: list[dict]) -> dict[str, list[str]]:
    def distinct(vals):
        return sorted({v for v in vals if v})
    return {
        "hosts": distinct(e["host"] for e in events),
        "users": distinct(e.get("user") for e in events),
        "dst_ips": distinct(_get(e, "net.dst_ip") for e in events),
        "dst_hosts": distinct(_get(e, "net.dst_host") for e in events),
    }


_VAR = re.compile(r"^\$\{(s[1-6])\.(hosts|users|dst_ips|dst_hosts)\}$")


def _resolve(value: Any, derived: dict[str, dict[str, list[str]]]) -> tuple[Any, bool]:
    """Return (value with variables replaced, has_empty_variable)."""
    if isinstance(value, str):
        m = _VAR.match(value)
        if m:
            vals = derived.get(m.group(1), {}).get(m.group(2), [])[:MAX_VAR_VALUES]
            return vals, not vals
    return value, False


def mock_run_plan(plan: HuntPlan, os_client: Any, run_id: str) -> tuple[list[StepResult], dict[str, list[dict]]]:
    """Canned run_plan: evaluates the plan filters in memory over the fixture events (no OpenSearch)."""
    all_events = load_fixture_events()
    start, end = plan.time_range.start, plan.time_range.end
    in_range = [e for e in all_events if start <= parse_ts(e["ts"]) <= end]
    results: list[StepResult] = []
    evidence: dict[str, list[dict]] = {}
    derived: dict[str, dict[str, list[str]]] = {}
    for step in plan.steps:
        t0 = datetime.now(timezone.utc)
        conds, empty = [], False
        for c in step.query.filters:
            val, miss = _resolve(c.value, derived)
            empty = empty or miss
            conds.append((c.field, c.op, val))
        matched = [] if empty else [e for e in in_range if all(_cmp(_get(e, f), op, v) for f, op, v in conds)]
        matched = matched[:min(step.query.size, MAX_EVIDENCE)]
        derived[step.step_id] = _derived(matched)
        evidence[step.step_id] = matched
        d = derived[step.step_id]
        ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
        results.append(StepResult(step_id=step.step_id, event_count=len(matched), hosts=d["hosts"],
                                  users=d["users"], dst_ips=d["dst_ips"], duration_ms=ms))
    return results, evidence


# ---------------------------------------------------------------- canned alerts from the fixtures
RULE_META = {
    "HC-001": ("Office application spawned PowerShell", 4, ["Execution"], ["T1566.001", "T1059.001"]),
    "HC-002": ("Encoded PowerShell command", 3, ["Execution"], ["T1059.001"]),
    "HC-003": ("Encoded PowerShell followed by outbound connection", 4, ["Command and Control"], ["T1071.001"]),
    "HC-004": ("Remote execution tool with remote target", 4, ["Lateral Movement"], ["T1021.002", "T1047"]),
    "HC-005": ("Internal fan-out on remote admin ports", 4, ["Lateral Movement"], ["T1021"]),
    "HC-006": ("PsExec service started", 4, ["Lateral Movement"], ["T1569.002"]),
    "HC-007": ("LSASS memory dump", 5, ["Credential Access"], ["T1003.001"]),
    "HC-008": ("Credential store extraction", 5, ["Credential Access"], ["T1003.002", "T1003.003"]),
    "HC-010": ("Executable dropped in AppData Roaming", 3, ["Initial Access"], ["T1204.002"]),
}
_ENC = re.compile(r"(?i)\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}")
_REMOTE = re.compile(r"(?i)(\\\\[\w.\-]+|/node:|\s-r:)")
_LSASS = re.compile(r"(?i)procdump.*lsass|comsvcs\.dll.*minidump")
_HIVE = re.compile(r"(?i)reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system)|ntdsutil")
_ROAMING = re.compile(r"(?i)\\appdata\\roaming\\.*\.(?:exe|dll)$")


def _proc(ev: dict) -> dict:
    return ev.get("process") or {}


def _single_rules(ev: dict) -> list[str]:
    """Rule ids of the single-event rules that match this event (mock rule logic)."""
    hits: list[str] = []
    p, cmd = _proc(ev), (_proc(ev).get("cmdline") or "")
    if ev["event_type"] == "process_create":
        ps = p.get("name") == "powershell.exe"
        if ps and p.get("parent_name") in ("winword.exe", "excel.exe", "outlook.exe"):
            hits.append("HC-001")
        if ps and _ENC.search(cmd) and not (ev["host"] == "WS-08" and ev.get("user") == "adm_it"):
            hits.append("HC-002")
        if (p.get("name") in ("psexec.exe", "wmic.exe", "winrs.exe") and _REMOTE.search(cmd)
                and not (ev["host"] == "WS-08" and ev.get("user") == "adm_it")):
            hits.append("HC-004")
        if p.get("name") == "psexesvc.exe":
            hits.append("HC-006")
        if _LSASS.search(cmd):
            hits.append("HC-007")
        if _HIVE.search(cmd):
            hits.append("HC-008")
    if ev["event_type"] == "file_create" and _ROAMING.search((ev.get("file") or {}).get("path", "")):
        hits.append("HC-010")
    return hits


def _mk_alert(rule_id: str, host: str, evs: list[dict], now: datetime) -> Alert:
    name, sev, tactics, techs = RULE_META[rule_id]
    first, last = parse_ts(evs[0]["ts"]), parse_ts(evs[-1]["ts"])
    return Alert(alert_id=sha1_hex(rule_id, host, first.isoformat()), rule_id=rule_id, rule_name=name,
                 severity=sev, technique_ids=techs, tactics=tactics, host=host, user=evs[0].get("user", ""),
                 ts_first=first, ts_last=last, event_ids=[e["event_id"] for e in evs],
                 summary=f"{name} on {host} ({len(evs)} event(s))", status="new", created_at=now)


def _multi_rules(events: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """HC-003 (encoded PowerShell then outbound connection) and HC-005 (internal fan-out), per host."""
    out: dict[tuple[str, str], list[dict]] = {}
    by_host: dict[str, list[dict]] = {}
    for e in events:
        by_host.setdefault(e["host"], []).append(e)
    for host, evs in by_host.items():
        for i, e in enumerate(evs):
            if e["event_type"] == "process_create" and _proc(e).get("name") == "powershell.exe" and _ENC.search(
                    _proc(e).get("cmdline", "")) and not (host == "WS-08" and e.get("user") == "adm_it"):
                t = parse_ts(e["ts"])
                nxt = [x for x in evs[i + 1:] if x["event_type"] == "network_conn"
                       and (x.get("net") or {}).get("direction") == "outbound"
                       and parse_ts(x["ts"]) - t <= timedelta(seconds=120)]
                if nxt:
                    out.setdefault(("HC-003", host), [e] + nxt)
        conns = [x for x in evs if x["event_type"] == "network_conn" and (x.get("net") or {}).get("direction")
                 == "internal" and (x["net"].get("dst_port") in (445, 135, 5985)) and x.get("user") != "svc_backup"]
        for j, c in enumerate(conns):
            t = parse_ts(c["ts"])
            win = [x for x in conns[j:] if parse_ts(x["ts"]) - t <= timedelta(seconds=600)]
            if len({x["net"]["dst_ip"] for x in win}) >= 4:
                out.setdefault(("HC-005", host), win)
    return out


def mock_alerts(events: list[dict], now: Optional[datetime] = None) -> list[Alert]:
    """Deterministic alerts derived from events with a small copy of the Section 8 rules."""
    now = now or datetime(2026, 11, 12, tzinfo=timezone.utc)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for e in events:
        for rid in _single_rules(e):
            grouped.setdefault((rid, e["host"]), []).append(e)
    grouped.update(_multi_rules(events))
    return [_mk_alert(r, h, evs, now) for (r, h), evs in sorted(grouped.items())]


class FixtureBackend:
    """Telemetry backend over the fixture events (HC_MOCK_HUNT=1). Same interface as OpenSearchBackend."""

    client = None
    mock = True

    def __init__(self) -> None:
        self._events = load_fixture_events()
        self._alerts = mock_alerts(self._events)

    def ping(self) -> bool:
        return True

    def newest_event_ts(self) -> Optional[datetime]:
        return parse_ts(self._events[-1]["ts"]) if self._events else None

    def count_events(self) -> int:
        return len(self._events)

    def get_events(self, ids: list[str]) -> list[dict]:
        want = set(ids)
        return [e for e in self._events if e["event_id"] in want]

    def search_alerts(self, status: str = "", rule_id: str = "", host: str = "", limit: int = 100):
        items = [a for a in self._alerts if (not status or a.status == status) and (not rule_id or a.rule_id == rule_id)
                 and (not host or a.host == host)]
        items.sort(key=lambda a: a.ts_first, reverse=True)
        return items[:limit], len(items)

    def alerts_for_hosts(self, hosts: list[str], start: datetime, end: datetime) -> list[Alert]:
        return [a for a in self._alerts if a.host in hosts and a.ts_last >= start and a.ts_first <= end]

    def count_alerts(self) -> int:
        return len(self._alerts)

    def index_finding(self, finding: Any) -> None:
        return None


# ---------------------------------------------------------------- canned ml
def label_for(confidence: float) -> str:
    """80 or more high, 60 to 79 medium, below 60 low (spec 9.3)."""
    return "high" if confidence >= 80 else "medium" if confidence >= 60 else "low"


class MockMl:
    """Canned ScoredWindow and confidence responses (HC_MOCK_ML=1)."""

    mock = True

    def health(self) -> str:
        return "mock"

    def windows(self, tr: TimeRange, hosts: list[str], run_id: str) -> list[ScoredWindow]:
        out = []
        for host in sorted(hosts):
            out.append(ScoredWindow(
                window_id=sha1_hex(host, tr.start.isoformat()), host=host, ts_first=tr.start,
                ts_last=tr.start + timedelta(minutes=15), event_ids=[], anomaly_if=0.8, anomaly_seq=0.6,
                anomaly=0.72, uncertainty=0.18,
                top_features=[FeatureContribution(name="n_smb_winrm", value=12.0, z=6.1),
                              FeatureContribution(name="n_ps_encoded", value=1.0, z=4.8)]))
        return out

    def confidence(self, window: ScoredWindow, stages_found: list[str], expected_stages: list[str],
                   hosts: list[str]) -> tuple[ScoreBreakdown, str]:
        return mock_confidence(window, stages_found, expected_stages, hosts)


def mock_confidence(window: ScoredWindow, stages_found: list[str], expected: list[str],
                    hosts: list[str]) -> tuple[ScoreBreakdown, str]:
    """Formula of spec 9.3 with the deterministic rationale text."""
    found = [s for s in expected if s in stages_found]
    cov = len(found) / len(expected) if expected else 0.0
    crit_by_host = {h: CRITICALITY.get(h, 2) for h in hosts}
    top_host = sorted(crit_by_host, key=lambda h: (-crit_by_host[h], h))[0] if crit_by_host else ""
    crit = crit_by_host.get(top_host, 0) / 5
    a, u = window.anomaly, window.uncertainty
    conf = round(100 * (0.35 * a + 0.25 * cov + 0.20 * crit + 0.20 * (1 - u)), 1)
    scores = ScoreBreakdown(anomaly_if=window.anomaly_if, anomaly_seq=window.anomaly_seq, anomaly=a,
                            coverage=cov, criticality=crit, uncertainty=u, confidence=conf)
    signals = ", ".join(f"{f.name} = {f.value:g} (z = {f.z:.1f})" for f in window.top_features) or "none"
    text = (f"Confidence {round(conf)} of 100 ({label_for(conf)}). "
            f"Anomaly strength {a:.2f} (isolation forest {window.anomaly_if:.2f}, sequence model "
            f"{window.anomaly_seq:.2f}). Evidence coverage {len(found)} of {len(expected)} expected stages "
            f"({', '.join(found) or 'none'}). Asset criticality {crit_by_host.get(top_host, 0)} of 5 "
            f"({top_host or 'n/a'}). Model uncertainty {u:.2f}. Strongest signals: {signals}.")
    return scores, text
