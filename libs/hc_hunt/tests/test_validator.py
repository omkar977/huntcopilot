"""One test per validator rule V0 to V10 plus the dst_hosts addendum. Owner: M2."""
from datetime import timedelta

import pytest

from hc_hunt.validator import validate_plan

from .plans import END, START, demo_plan, f, plan, step

OK_STEP = step("s1", [f("event_type", "eq", "process_create")])


def verdict(steps, **kw):
    return validate_plan(plan(steps, **kw))


def has(result, code):
    return any(e.startswith(code + ":") for e in result.errors)


def test_demo_plan_is_valid():
    result = validate_plan(demo_plan())
    assert result.ok and result.errors == []


def test_v1_step_count():
    assert has(verdict([]), "V1")
    seven = [step(f"s{i}", [f("host", "eq", "WS-01")]) for i in range(1, 8)]
    assert has(verdict(seven), "V1")
    six = [step(f"s{i}", [f("host", "eq", "WS-01")]) for i in range(1, 7)]
    assert verdict(six).ok


def test_v2_step_ids_form_and_uniqueness():
    assert has(verdict([step("s7", [f("host", "eq", "a")])]), "V2")
    assert has(verdict([step("x1", [f("host", "eq", "a")])]), "V2")
    assert has(verdict([step("s1", [f("host", "eq", "a")]), step("s1", [f("host", "eq", "b")])]), "V2")


def test_v3_depends_on_only_earlier_steps():
    assert has(verdict([step("s1", [f("host", "eq", "a")], depends_on=["s2"]), step("s2", [f("host", "eq", "b")])]), "V3")
    assert has(verdict([step("s1", [f("host", "eq", "a")], depends_on=["s1"])]), "V3")
    assert has(verdict([step("s1", [f("host", "eq", "a")], depends_on=["s5"])]), "V3")


def test_v4_size_range():
    result = validate_plan(plan([step("s1", [f("host", "eq", "a")])]).model_copy(deep=True))
    bad = plan([step("s1", [f("host", "eq", "a")])])
    bad.steps[0].query.size = 501           # model_copy style assignment skips pydantic checks
    assert has(validate_plan(bad), "V4")
    bad.steps[0].query.size = 0
    assert has(validate_plan(bad), "V4")
    assert result.ok


def test_v5_time_range():
    assert has(verdict([OK_STEP], start=END, end=START), "V5")
    assert has(verdict([OK_STEP], start=START, end=START), "V5")
    assert has(verdict([OK_STEP], start=START, end=START + timedelta(days=7, seconds=1)), "V5")
    assert verdict([OK_STEP], start=START, end=START + timedelta(days=7)).ok
    naive = plan([OK_STEP])
    naive.time_range.start = naive.time_range.start.replace(tzinfo=None)
    assert has(validate_plan(naive), "V5")


def test_v6_at_most_eight_filters():
    nine = [f("host", "neq", f"h{i}") for i in range(9)]
    assert has(verdict([step("s1", nine)]), "V6")
    assert verdict([step("s1", nine[:8])]).ok


@pytest.mark.parametrize("field,op,value", [
    ("net.dst_port", "contains", 445), ("net.dst_port", "startswith", 4), ("auth.logon_type", "contains", 3),
    ("ts", "eq", "2026-11-12T00:00:00Z"), ("ts", "in", ["2026-11-12T00:00:00Z"]),
    ("host", "gt", "a"), ("process.name", "lte", "a"), ("dns.query", "gte", "a"),
])
def test_v7_operator_not_allowed_for_field(field, op, value):
    assert has(verdict([step("s1", [f(field, op, value)])]), "V7")


@pytest.mark.parametrize("field,op,value", [
    ("net.dst_port", "gt", 1024), ("net.dst_port", "in", [445, 135]), ("auth.logon_type", "eq", 3),
    ("ts", "gte", "2026-11-12T00:00:00Z"), ("host", "contains", "WS"), ("file.path", "startswith", "C:"),
    ("tags", "eq", "x"), ("net.dst_ip", "eq", "203.0.113.50"), ("net.dst_ip", "startswith", "10.10."),
])
def test_v7_allowed_operators_pass(field, op, value):
    assert verdict([step("s1", [f(field, op, value)])]).ok


def test_v7_value_types():
    assert has(verdict([step("s1", [f("net.dst_port", "eq", "445")])]), "V7")
    assert has(verdict([step("s1", [f("host", "eq", ["a", "b"])])]), "V7")
    assert has(verdict([step("s1", [f("host", "in", "WS-01")])]), "V7")
    assert has(verdict([step("s1", [f("ts", "gte", "yesterday")])]), "V7")
    assert has(verdict([step("s1", [f("net.dst_ip", "eq", "999.1.1.1")])]), "V7")
    assert has(verdict([step("s1", [f("net.dst_ip", "contains", "10.")])]), "V7")
    assert has(verdict([step("s1", [f("net.dst_ip", "startswith", "abc")])]), "V7")


def test_v8_string_values():
    assert has(verdict([step("s1", [f("host", "eq", "x" * 201)])]), "V8")
    assert verdict([step("s1", [f("host", "eq", "x" * 200)])]).ok
    assert has(verdict([step("s1", [f("process.cmdline", "contains", "*enc")])]), "V8")
    assert has(verdict([step("s1", [f("process.cmdline", "contains", "?enc")])]), "V8")
    assert verdict([step("s1", [f("process.cmdline", "contains", "enc*")])]).ok
    assert has(verdict([step("s1", [f("process.cmdline", "contains", "a\x00b")])]), "V8")
    assert has(verdict([step("s1", [f("process.cmdline", "contains", "a\nb")])]), "V8")
    assert has(verdict([step("s1", [f("host", "in", ["ok", "*bad"])])]), "V8")


def test_v9_variables():
    first = step("s1", [f("event_type", "eq", "process_create")])
    good = step("s2", [f("host", "in", "${s1.hosts}")], depends_on=["s1"])
    assert verdict([first, good]).ok
    for kind in ("hosts", "users", "dst_ips", "dst_hosts"):
        assert verdict([first, step("s2", [f("host", "in", "${s1.%s}" % kind)], depends_on=["s1"])]).ok
    not_depended = step("s2", [f("host", "in", "${s1.hosts}")])
    assert has(verdict([first, not_depended]), "V9")
    assert has(verdict([first, step("s2", [f("host", "in", "${s1.secrets}")], depends_on=["s1"])]), "V9")
    assert has(verdict([first, step("s2", [f("host", "in", "x${s1.hosts}")], depends_on=["s1"])]), "V9")
    assert has(verdict([first, step("s2", [f("host", "in", "${s9.hosts}")], depends_on=["s1"])]), "V9")
    assert has(verdict([first, step("s2", [f("host", "eq", "${s1.hosts}")], depends_on=["s1"])]), "V9")
    assert has(verdict([first, step("s2", [f("host", "in", ["${s1.hosts}"])], depends_on=["s1"])]), "V9")


def test_v10_group_by_must_be_allowed():
    assert has(verdict([step("s1", [f("host", "eq", "a")], group_by="gt.scenario")]), "V10")
    assert has(verdict([step("s1", [f("host", "eq", "a")], group_by="process.pid")]), "V10")
    assert verdict([step("s1", [f("event_type", "eq", "dns_query")], group_by="dns.query")]).ok


def test_v0_field_allow_list_rejects_ground_truth_and_unknown_fields():
    for field in ("gt.is_malicious", "gt.scenario", "gt.stage", "gt", "process.pid", "ingested_at", "net.src_ip"):
        assert has(verdict([step("s1", [f(field, "eq", "x")])]), "V0"), field


def test_warnings_do_not_fail_the_plan():
    result = validate_plan(plan([step("s1", [])], expected=("execution", "made_up")))
    assert result.ok
    assert any("no filters" in w for w in result.warnings)
    assert any("made_up" in w for w in result.warnings)
    stage = validate_plan(plan([step("s1", [f("host", "eq", "a")], stage="nonsense")]))
    assert stage.ok and any("nonsense" in w for w in stage.warnings)


def test_all_errors_are_reported_together():
    result = verdict([step("s1", [f("gt.is_malicious", "eq", "true")], depends_on=["s3"], group_by="x")], start=END, end=START)
    assert {e.split(":")[0] for e in result.errors} >= {"V0", "V3", "V5", "V10"}
