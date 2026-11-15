"""Executor: DSL generation without OpenSearch, variable resolution and run_plan. Owner: M2."""
import json

import pytest

from hc_common.schemas import TimeRange
from hc_detect.timeutil import parse_ts
from hc_hunt.executor import PlanValidationError, build_query, earliest_dependency_ts, escape_wildcard, run_plan, step_context

from .plans import END, START, demo_plan, f, plan, step

RANGE = TimeRange(start=START, end=END)
TS_FILTER = {"range": {"ts": {"gte": "2026-11-12T00:00:00Z", "lte": "2026-11-12T23:59:59Z"}}}


def body_for(filters, variables=None, **kw):
    return build_query(plan([step("s2", filters, **kw)]).steps[0], RANGE, variables)


def test_appendix_e_example_matches_exactly():
    s2 = demo_plan().steps[1]
    body = build_query(s2, RANGE, {"s1.hosts": ["WS-03"]})
    assert body == {
        "size": 200,
        "sort": [{"ts": "asc"}],
        "_source": {"excludes": ["gt"]},
        "query": {"bool": {"filter": [
            {"term": {"event_type": "network_conn"}},
            {"term": {"net.direction": "internal"}},
            {"terms": {"net.dst_port": [445, 135, 5985]}},
            {"terms": {"host": ["WS-03"]}},
            TS_FILTER,
        ]}},
    }


def test_ground_truth_is_always_excluded_from_source():
    for filters in ([f("host", "eq", "a")], [], [f("process.cmdline", "contains", "x")]):
        assert body_for(filters)["_source"] == {"excludes": ["gt"]}


def test_no_user_value_is_ever_a_wildcard_pattern():
    evil = r"*\\?a*b"
    body = body_for([f("file.path", "contains", evil)])
    clause = body["query"]["bool"]["filter"][0]["wildcard"]["file.path"]
    assert clause["value"] == "*" + escape_wildcard(evil) + "*"
    assert clause["value"] == r"*\*\\\\\?a\*b*" and clause["case_insensitive"] is True
    # only the executor adds the outer asterisks; eq never becomes a wildcard
    assert "wildcard" not in json.dumps(body_for([f("file.path", "eq", "a*b")]))
    assert body_for([f("user", "eq", "a*b")])["query"]["bool"]["filter"][0] == {"term": {"user": "a*b"}}


def test_escape_wildcard():
    assert escape_wildcard("a*b?c\\d") == "a\\*b\\?c\\\\d"
    assert escape_wildcard("plain") == "plain"


def test_clause_shapes_per_field_type_and_operator():
    cases = {
        ("process.cmdline", "contains", "-enc"): {"match_phrase": {"process.cmdline": "-enc"}},
        ("process.cmdline", "eq", "x y"): {"match_phrase": {"process.cmdline": "x y"}},
        ("process.cmdline", "startswith", "power"): {"match_phrase_prefix": {"process.cmdline": "power"}},
        ("process.cmdline", "in", ("a", "b")): {"bool": {"should": [{"match_phrase": {"process.cmdline": "a"}},
                                                                    {"match_phrase": {"process.cmdline": "b"}}],
                                                         "minimum_should_match": 1}},
        ("host", "startswith", "WS"): {"prefix": {"host": {"value": "WS", "case_insensitive": True}}},
        ("net.dst_port", "gte", 1024): {"range": {"net.dst_port": {"gte": 1024}}},
        ("auth.logon_type", "eq", 3): {"term": {"auth.logon_type": 3}},
        ("net.dst_ip", "eq", "203.0.113.50"): {"term": {"net.dst_ip": "203.0.113.50"}},
        ("net.dst_ip", "in", ("1.1.1.1", "2.2.2.2")): {"terms": {"net.dst_ip": ["1.1.1.1", "2.2.2.2"]}},
        ("net.dst_ip", "startswith", "10.10."): {"term": {"net.dst_ip": "10.10.0.0/16"}},
        ("net.dst_ip", "startswith", "10."): {"term": {"net.dst_ip": "10.0.0.0/8"}},
        ("net.dst_ip", "startswith", "10.10.2."): {"term": {"net.dst_ip": "10.10.2.0/24"}},
        ("net.dst_ip", "startswith", "10.10.2.21"): {"term": {"net.dst_ip": "10.10.2.21"}},
        ("ts", "gt", "2026-11-12T01:00:00+00:00"): {"range": {"ts": {"gt": "2026-11-12T01:00:00Z"}}},
        ("tags", "eq", "train"): {"term": {"tags": "train"}},
    }
    for (field, op, value), expected in cases.items():
        value = list(value) if isinstance(value, tuple) else value
        assert body_for([f(field, op, value)])["query"]["bool"]["filter"][0] == expected, (field, op)


def test_neq_goes_to_must_not_and_range_filter_stays_last():
    body = body_for([f("user", "neq", "adm_it"), f("host", "eq", "WS-03")])
    boolean = body["query"]["bool"]
    assert boolean["must_not"] == [{"term": {"user": "adm_it"}}]
    assert boolean["filter"] == [{"term": {"host": "WS-03"}}, TS_FILTER]
    assert "must_not" not in body_for([f("host", "eq", "a")])["query"]["bool"]


def test_group_by_adds_terms_aggregation_and_size():
    body = body_for([f("event_type", "eq", "dns_query")], group_by="dns.query", size=50)
    assert body["size"] == 50 and body["aggs"] == {"group": {"terms": {"field": "dns.query", "size": 50}}}
    raw = body_for([f("event_type", "eq", "process_create")], group_by="process.cmdline")
    assert raw["aggs"]["group"]["terms"]["field"] == "process.cmdline.raw"
    assert "aggs" not in body_for([f("host", "eq", "a")])


def test_variables_resolve_cap_at_50_and_empty_means_no_query():
    flt = [f("host", "in", "${s1.hosts}")]
    values = [f"H-{i:03d}" for i in range(80)]
    body = body_for(flt, {"s1.hosts": values}, depends_on=["s1"])
    assert body["query"]["bool"]["filter"][0] == {"terms": {"host": values[:50]}}
    assert body_for(flt, {"s1.hosts": []}, depends_on=["s1"]) is None
    assert body_for(flt, {}, depends_on=["s1"]) is None


class FakeOpenSearch:
    """Answers each search from a list of canned event lists and records every body."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def search(self, index, body):
        self.calls.append((index, body))
        events = self.answers.pop(0) if self.answers else []
        return {"hits": {"hits": [{"_source": dict(e)} for e in events]}}


def ev(host, event_type="process_create", dst_host="", dst_ip="", user="carol", **extra):
    base = {"event_id": f"{host}-{dst_ip or event_type}", "ts": "2026-11-12T09:30:00Z", "host": host, "user": user,
            "event_type": event_type, "gt": {"is_malicious": True, "scenario": "x", "stage": "y"}}
    if dst_ip:
        base["net"] = {"dst_ip": dst_ip, "dst_port": 445, "direction": "internal", "dst_host": dst_host}
    base.update(extra)
    return base


def test_run_plan_chains_variables_and_strips_ground_truth():
    s1 = [ev("WS-03"), ev("WS-08", user="adm_it")]
    s2 = [ev("WS-03", "network_conn", dst_host="FILE-01", dst_ip="10.10.2.21"),
          ev("WS-03", "network_conn", dst_host="DB-01", dst_ip="10.10.2.31")]
    s3 = [ev("FILE-01", "auth"), ev("DB-01", "auth")]
    s4 = [ev("WS-03")]
    client = FakeOpenSearch([s1, s2, s3, s4])
    results, evidence = run_plan(demo_plan(), client, "run1")
    assert [r.step_id for r in results] == ["s1", "s2", "s3", "s4"]
    assert results[0].hosts == ["WS-03", "WS-08"] and results[0].users == ["adm_it", "carol"]
    assert results[1].dst_ips == ["10.10.2.21", "10.10.2.31"] and results[1].event_count == 2
    assert all(r.duration_ms >= 0 for r in results)
    assert set(evidence) == {"s1", "s2", "s3", "s4"}
    assert all("gt" not in e for events in evidence.values() for e in events)
    # variables were resolved from earlier results
    assert {"terms": {"host": ["WS-03", "WS-08"]}} in client.calls[1][1]["query"]["bool"]["filter"]
    assert {"terms": {"host": ["DB-01", "FILE-01"]}} in client.calls[2][1]["query"]["bool"]["filter"]
    assert client.calls[0][0].endswith("-*")
    assert all(call[1]["_source"] == {"excludes": ["gt"]} for call in client.calls)


def test_run_plan_step_with_unresolved_variable_returns_zero_without_searching():
    client = FakeOpenSearch([[]])  # s1 finds nothing
    results, evidence = run_plan(demo_plan(), client, "run2")
    assert [r.event_count for r in results] == [0, 0, 0, 0 + 0]
    assert len(client.calls) == 2   # s1 and s4 (s4 has no variables); s2 and s3 are skipped
    assert evidence["s2"] == [] and evidence["s3"] == []


def test_run_plan_rejects_invalid_plan_without_searching():
    bad = plan([step("s1", [f("gt.is_malicious", "eq", "true")])])
    client = FakeOpenSearch([])
    with pytest.raises(PlanValidationError) as info:
        run_plan(bad, client, "run3")
    assert any(e.startswith("V0") for e in info.value.errors) and client.calls == []


def test_run_plan_caps_evidence_at_500_per_step():
    many = [ev("WS-03", dst_ip="1.1.1.1") for _ in range(650)]
    results, evidence = run_plan(plan([step("s1", [f("host", "eq", "WS-03")], size=500)]), FakeOpenSearch([many]), "r")
    assert len(evidence["s1"]) == 500 and results[0].event_count == 500


def test_step_context_values_are_sorted_and_distinct():
    ctx = step_context([ev("B"), ev("A"), ev("A", "network_conn", dst_host="X", dst_ip="1.1.1.1"),
                        ev("C", "network_conn", dst_host="", dst_ip="2.2.2.2")])
    assert ctx == {"hosts": ["A", "B", "C"], "users": ["carol"], "dst_ips": ["1.1.1.1", "2.2.2.2"], "dst_hosts": ["X"]}


def test_dependent_step_queries_from_earliest_dependency_event_to_plan_end():
    s1 = [dict(ev("WS-03"), ts="2026-11-12T09:30:08Z"), dict(ev("WS-08"), ts="2026-11-12T09:12:00Z")]
    client = FakeOpenSearch([s1, [], [], []])
    run_plan(demo_plan(), client, "dep")
    def rng(i):
        return client.calls[i][1]["query"]["bool"]["filter"][-1]["range"]["ts"]
    assert rng(0) == {"gte": "2026-11-12T00:00:00Z", "lte": "2026-11-12T23:59:59Z"}   # s1 has no dependency
    assert rng(1) == {"gte": "2026-11-12T09:12:00Z", "lte": "2026-11-12T23:59:59Z"}   # s2 depends on s1
    assert rng(len(client.calls) - 1)["gte"] == "2026-11-12T09:12:00Z"                # s4 depends on s1


def test_time_bound_never_widens_the_plan_range_and_skips_when_dependency_empty():
    step_ = demo_plan().steps[1]
    early = build_query(step_, RANGE, {"s1.hosts": ["WS-03"]}, start=parse_ts("2026-11-11T00:00:00Z"))
    assert early["query"]["bool"]["filter"][-1] == TS_FILTER
    assert earliest_dependency_ts(step_, {"s1": []}) is None


def test_late_malicious_events_are_not_cut_by_the_time_bound_design():
    # dependency starts late in the day: the dependent step no longer scans the quiet morning
    s1 = [dict(ev("WS-03"), ts="2026-11-12T14:00:00Z")]
    client = FakeOpenSearch([s1, [], [], []])
    run_plan(demo_plan(), client, "late")
    assert client.calls[1][1]["query"]["bool"]["filter"][-1]["range"]["ts"]["gte"] == "2026-11-12T14:00:00Z"
