"""The local V1..V10 validator and chain helpers (used only when hc_hunt is absent)."""
from datetime import datetime, timedelta, timezone

import pytest

from agent.templates import TEMPLATES
from hc_api.hunt_local import build_chain, chain_to_dot, validate_plan
from hc_common.schemas import Cond, HuntStep, Query, TimeRange

T0 = datetime(2026, 11, 12, 9, tzinfo=timezone.utc)
TR = TimeRange(start=T0, end=T0 + timedelta(hours=2))


def plan(**over):
    p = TEMPLATES["lateral_after_powershell"](TR, "x")
    return p.model_copy(update=over)


def step(sid, filters, deps=(), size=200, group_by=None):
    # model_construct skips pydantic's own range check so the validator itself is what we test
    q = Query.model_construct(filters=filters, size=size, group_by=group_by)
    return HuntStep.model_construct(step_id=sid, description="d", depends_on=list(deps), stage="execution",
                                    expected_evidence="", query=q)


def c(field, op, value):
    return Cond(field=field, op=op, value=value)


def errs(steps=None, tr=None):
    kw = {}
    if steps is not None:
        kw["steps"] = steps
    if tr is not None:
        kw["time_range"] = tr
    return validate_plan(plan(**kw)).errors


def test_valid_demo_plan():
    assert validate_plan(plan()).ok


def test_v1_step_count():
    assert any("1 to 6" in e for e in errs([]))
    many = [step(f"s{i}", [c("host", "eq", "a")]) for i in range(1, 7)] + [step("s7", [c("host", "eq", "a")])]
    assert any("1 to 6" in e for e in errs(many))


def test_v2_step_ids():
    assert any("unique" in e for e in errs([step("s1", [c("host", "eq", "a")]), step("s1", [c("host", "eq", "a")])]))
    assert any("s1..s6" in e for e in errs([step("x1", [c("host", "eq", "a")])]))


def test_v3_depends_on_earlier_only():
    assert any("earlier" in e for e in errs([step("s1", [c("host", "eq", "a")], deps=["s2"]),
                                             step("s2", [c("host", "eq", "a")])]))
    assert any("earlier" in e for e in errs([step("s1", [c("host", "eq", "a")], deps=["s9"])]))


def test_v4_size():
    assert any("size" in e for e in errs([step("s1", [c("host", "eq", "a")], size=0)]))
    assert any("size" in e for e in errs([step("s1", [c("host", "eq", "a")], size=501)]))
    assert not errs([step("s1", [c("host", "eq", "a")], size=500)])


def test_v5_time_range():
    assert any("after start" in e for e in errs(tr=TimeRange(start=T0, end=T0)))
    assert any("7 days" in e for e in errs(tr=TimeRange(start=T0, end=T0 + timedelta(days=7, seconds=1))))
    assert not errs(tr=TimeRange(start=T0, end=T0 + timedelta(days=7)))


def test_v6_filter_count():
    nine = [c("host", "eq", str(i)) for i in range(9)]
    assert any("8 filters" in e for e in errs([step("s1", nine)]))


@pytest.mark.parametrize("field,op", [("net.dst_port", "contains"), ("auth.logon_type", "startswith"),
                                      ("ts", "eq"), ("host", "gt"), ("process.name", "lt")])
def test_v7_operator_per_field(field, op):
    value = 5 if field in ("net.dst_port", "auth.logon_type") else "x"
    assert any("not allowed for" in e for e in errs([step("s1", [c(field, op, value)])]))


def test_v7_allowed_ops_pass():
    assert not errs([step("s1", [c("net.dst_port", "gte", 100), c("ts", "lt", "2026-11-12T10:00:00Z"),
                                 c("host", "startswith", "WS")])])


@pytest.mark.parametrize("value,needle", [("*evil", "wildcard"), ("?x", "wildcard"), ("a" * 201, "200"),
                                          ("bad\x07char", "control")])
def test_v8_string_values(value, needle):
    assert any(needle in e for e in errs([step("s1", [c("host", "eq", value)])]))


def test_v8_applies_to_list_items():
    assert any("wildcard" in e for e in errs([step("s1", [c("host", "in", ["ok", "*bad"])])]))


@pytest.mark.parametrize("value", ["${s1.nothing}", "${s9.hosts}", "${bad}", "x${s1.hosts}"])
def test_v9_bad_variable_forms(value):
    assert errs([step("s1", [c("host", "eq", "a")]), step("s2", [c("host", "eq", value)], deps=["s1"])])


def test_v9_variable_needs_depends_on_and_dst_hosts_allowed():
    assert any("depends_on" in e for e in errs([step("s1", [c("host", "eq", "a")]),
                                                step("s2", [c("host", "in", "${s1.hosts}")])]))
    assert not errs([step("s1", [c("host", "eq", "a")]), step("s2", [c("host", "in", "${s1.dst_hosts}")], deps=["s1"])])


@pytest.mark.parametrize("field", ["gt.is_malicious", "gt.scenario", "process.pid", "net.src_ip", "ingested_at"])
def test_disallowed_fields_rejected(field):
    assert any("not allowed" in e for e in errs([step("s1", [c(field, "eq", "x")])]))


def test_v10_group_by():
    assert any("group_by" in e for e in errs([step("s1", [c("host", "eq", "a")], group_by="gt.scenario")]))
    assert not errs([step("s1", [c("host", "eq", "a")], group_by="dns.query")])


def test_chain_and_dot_are_deterministic():
    ev = [
        {"event_id": "e1", "ts": "2026-11-12T09:00:00Z", "host": "WS-03", "event_type": "network_conn",
         "net": {"dst_ip": "10.10.2.21", "dst_port": 445, "dst_host": "FILE-01", "direction": "internal"}},
        {"event_id": "e2", "ts": "2026-11-12T09:01:00Z", "host": "WS-03", "event_type": "network_conn",
         "net": {"dst_ip": "203.0.113.50", "dst_port": 443, "dst_host": "", "direction": "outbound"}},
        {"event_id": "e3", "ts": "2026-11-12T09:02:00Z", "host": "FILE-01", "event_type": "auth",
         "auth": {"logon_type": 3, "result": "success", "target_user": "adm_it", "src_host": "WS-03"}},
        {"event_id": "e4", "ts": "2026-11-12T09:03:00Z", "host": "WS-03", "event_type": "dns_query",
         "dns": {"query": "cdn-sync.badhost.test"}},
        {"event_id": "e5", "ts": "2026-11-12T09:04:00Z", "host": "WS-03", "event_type": "process_create",
         "process": {"name": "powershell.exe", "pid": 10, "parent_name": "winword.exe", "parent_pid": 9}},
    ]
    a = build_chain(ev, {"WS-03": 0.9})
    b = build_chain(list(reversed(ev)), {"WS-03": 0.9})
    assert a == b
    kinds = sorted(e.kind for e in a.edges)
    assert kinds == ["authenticated", "connected", "connected", "queried", "spawned"]
    dot = chain_to_dot(a)
    assert dot.startswith("digraph") and dot.rstrip().endswith("}") and "#e53935" in dot and "#fb8c00" in dot
    assert dot == chain_to_dot(b)


def test_chain_node_cap():
    ev = [{"event_id": f"e{i}", "ts": f"2026-11-12T09:{i % 60:02d}:00Z", "host": "WS-03", "event_type": "dns_query",
           "dns": {"query": f"d{i}.test"}} for i in range(200)]
    ch = build_chain(ev, {})
    assert len(ch.nodes) <= 80 and any(n.id == "host:WS-03" for n in ch.nodes)
    assert all(e.src in {n.id for n in ch.nodes} and e.dst in {n.id for n in ch.nodes} for e in ch.edges)
