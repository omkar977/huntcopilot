"""Operator and engine semantics (spec Section 5.6, Appendix J). Owner: M2."""
import random

import pytest

from hc_detect.engine import MISSING, compile_condition, evaluate, get_path, matches
from hc_detect.loader import Condition, parse_rule

from .helpers import auth, dns, net, proc


def cond(field, op, value=None):
    return Condition(field=field, op=op, value=value)


def single_rule(where, exclusions=None, group_by=("host",)):
    return parse_rule({
        "id": "HC-900", "name": "Test rule", "severity": 3, "type": "single",
        "group_by": list(group_by), "where": where, "exclusions": exclusions or [],
    })


def test_get_path_dotted_and_missing():
    ev = proc(0, "a.exe")
    assert get_path(ev, "process.name") == "a.exe"
    assert get_path(ev, "net.dst_ip") is MISSING          # null sub-object
    assert get_path(ev, "process.nothing") is MISSING
    assert get_path(ev, "host.name") is MISSING           # scalar cannot be descended


@pytest.mark.parametrize("op,value,actual,expected", [
    ("eq", "a.exe", "a.exe", True), ("eq", "a.exe", "A.EXE", False),
    ("neq", "a.exe", "b.exe", True), ("neq", "a.exe", "a.exe", False),
    ("in", ["a.exe", "b.exe"], "b.exe", True), ("in", ["a.exe"], "c.exe", False),
    ("contains", "LSASS", "procdump -ma lsass.exe", True), ("contains", "zzz", "procdump", False),
    ("startswith", "proc", "procdump", True), ("startswith", "Proc", "procdump", False),
    ("endswith", ".dmp", "x.dmp", True), ("endswith", ".dmp", "x.dmpx", False),
    ("regex", r"^PROC\w+$", "procdump", True), ("regex", r"^\d+$", "procdump", False),
])
def test_string_operators(op, value, actual, expected):
    ev = proc(0, "x.exe", cmdline=actual)
    assert compile_condition(cond("process.cmdline", op, value))(ev) is expected


@pytest.mark.parametrize("op,value,actual,expected", [
    ("gt", 445, 446, True), ("gt", 445, 445, False), ("gte", 445, 445, True),
    ("lt", 445, 135, True), ("lt", 445, 445, False), ("lte", 445, 445, True),
])
def test_numeric_operators(op, value, actual, expected):
    ev = net(0, "10.10.2.21", port=actual)
    assert compile_condition(cond("net.dst_port", op, value))(ev) is expected


def test_ts_comparison_operators():
    ev = proc(30, "a.exe")
    assert compile_condition(cond("ts", "gte", "2026-11-12T10:00:30Z"))(ev)
    assert not compile_condition(cond("ts", "lt", "2026-11-12T10:00:30Z"))(ev)


def test_exists_and_missing_field_semantics():
    ev = proc(0, "a.exe")
    assert compile_condition(cond("process.name", "exists", True))(ev)
    assert not compile_condition(cond("net.dst_ip", "exists", True))(ev)
    assert compile_condition(cond("net.dst_ip", "exists", False))(ev)
    assert not compile_condition(cond("process.name", "exists", False))(ev)
    # a missing field makes every other condition false, even neq
    assert not compile_condition(cond("net.dst_ip", "neq", "1.2.3.4"))(ev)
    assert not compile_condition(cond("net.dst_port", "lt", 10))(ev)


def test_list_valued_field_tags():
    ev = proc(0, "a.exe")
    ev["tags"] = ["train", "x"]
    assert compile_condition(cond("tags", "eq", "train"))(ev)
    assert compile_condition(cond("tags", "contains", "RAI"))(ev)
    assert not compile_condition(cond("tags", "neq", "train"))(ev)
    assert compile_condition(cond("tags", "neq", "zzz"))(ev)


def test_matches_is_and_of_conditions():
    ev = proc(0, "a.exe", parent="winword.exe")
    assert matches([cond("process.name", "eq", "a.exe"), cond("process.parent_name", "eq", "winword.exe")], ev)
    assert not matches([cond("process.name", "eq", "a.exe"), cond("process.parent_name", "eq", "x")], ev)


def test_single_one_alert_per_event_and_fields():
    rule = single_rule([{"field": "process.name", "op": "eq", "value": "a.exe"}])
    events = [proc(0, "a.exe", cmdline="a.exe " + "x" * 300), proc(10, "a.exe"), proc(20, "b.exe")]
    alerts = evaluate(rule, events)
    assert len(alerts) == 2
    first = alerts[0]
    assert first.ts_first == first.ts_last and first.host == "WS-03" and first.user == "carol"
    assert first.status == "new" and first.severity == 3 and first.event_ids == [events[0]["event_id"]]
    assert first.summary.startswith("Test rule: 1 event(s) on WS-03 | a.exe ")
    assert len(first.summary.split(" | ", 1)[1]) == 120


def test_alert_id_formula():
    from hc_common.ids import sha1_hex
    rule = single_rule([{"field": "process.name", "op": "eq", "value": "a.exe"}])
    alert = evaluate(rule, [proc(0, "a.exe")])[0]
    assert alert.alert_id == sha1_hex("HC-900", "WS-03", "2026-11-12T10:00:00Z")


def test_exclusions_any_list_fully_matching_ignores_event():
    rule = single_rule(
        [{"field": "process.name", "op": "eq", "value": "a.exe"}],
        exclusions=[
            [{"field": "host", "op": "eq", "value": "WS-08"}, {"field": "user", "op": "eq", "value": "adm_it"}],
            [{"field": "user", "op": "eq", "value": "svc_x"}],
        ],
    )
    events = [
        proc(0, "a.exe", host="WS-08", user="adm_it"),   # excluded (list 1 fully matches)
        proc(1, "a.exe", host="WS-08", user="heidi"),    # list 1 only half matches -> kept
        proc(2, "a.exe", user="svc_x"),                  # excluded (list 2)
        proc(3, "a.exe"),                                # kept
    ]
    assert [a.ts_first.second for a in evaluate(rule, events)] == [1, 3]


def test_event_missing_group_field_is_skipped():
    rule = single_rule([{"field": "event_type", "op": "eq", "value": "dns_query"}], group_by=("dns.query",))
    events = [dns(0, "x.test"), proc(1, "a.exe")]
    assert len(evaluate(rule, events)) == 1


def test_host_taken_from_last_event_when_not_grouped_by_host():
    rule = single_rule([{"field": "event_type", "op": "eq", "value": "process_create"}], group_by=("user",))
    alert = evaluate(rule, [proc(0, "a.exe", host="WS-05")])[0]
    assert alert.host == "WS-05"


def test_deterministic_idempotent_and_order_independent():
    rule = single_rule([{"field": "process.name", "op": "eq", "value": "a.exe"}])
    events = [proc(i * 7, "a.exe", event_id=f"id{i:03d}") for i in range(30)]
    first = evaluate(rule, events)
    shuffled = events[:]
    random.Random(5).shuffle(shuffled)
    assert evaluate(rule, events) == first
    assert evaluate(rule, shuffled) == first


def test_events_without_valid_ts_are_skipped_and_input_not_mutated():
    rule = single_rule([{"field": "process.name", "op": "eq", "value": "a.exe"}])
    good = proc(0, "a.exe")
    bad = proc(1, "a.exe")
    bad["ts"] = "not-a-time"
    events = [good, bad]
    snapshot = [dict(e) for e in events]
    assert len(evaluate(rule, events)) == 1
    assert events == snapshot


def test_engine_ignores_ground_truth():
    rule = single_rule([{"field": "process.name", "op": "eq", "value": "a.exe"}])
    a = proc(0, "a.exe")
    b = proc(0, "a.exe", event_id=a["event_id"])
    b["gt"] = {"is_malicious": True, "scenario": "phishing", "stage": "execution"}
    assert evaluate(rule, [a]) == evaluate(rule, [b])


def test_auth_condition_example():
    rule = single_rule([
        {"field": "event_type", "op": "eq", "value": "auth"},
        {"field": "auth.result", "op": "eq", "value": "failure"},
    ])
    alerts = evaluate(rule, [auth(0, result="failure", host="FILE-01"), auth(1, result="success")])
    assert [a.host for a in alerts] == ["FILE-01"]
