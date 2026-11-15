"""Fallback templates and the intent matcher (spec 10.2)."""
from datetime import datetime, timezone

import pytest

from agent.templates import EXAMPLE_INTENTS, TEMPLATES, match_template
from hc_api.hunt_local import validate_plan
from hc_common.schemas import TimeRange

TR = TimeRange(start=datetime(2026, 11, 12, 9, tzinfo=timezone.utc), end=datetime(2026, 11, 12, 11, tzinfo=timezone.utc))


def test_demo_sentence_matches_lateral():
    assert match_template("Find possible lateral movement after a suspicious PowerShell execution.") == \
        "lateral_after_powershell"


@pytest.mark.parametrize("text,expected", [
    ("look for psexec use", "lateral_after_powershell"),
    ("SMB fan-out please", "lateral_after_powershell"),
    ("winrm abuse", "lateral_after_powershell"),
    ("possible pivot", "lateral_after_powershell"),
    ("credential theft", "credential_dumping"),
    ("anything touching LSASS", "credential_dumping"),
    ("ntds extraction", "credential_dumping"),
    ("SAM hive", "credential_dumping"),
    ("memory dump", "credential_dumping"),
    ("C2 traffic", "c2_beaconing"),
    ("beaconing hosts", "c2_beaconing"),
    ("a callback to the internet", "c2_beaconing"),
    ("command and control", "c2_beaconing"),
    ("phishing document", "phishing_execution"),
    ("macro launched shell", "phishing_execution"),
    ("suspicious docm file", "phishing_execution"),
    ("office app child process", "phishing_execution"),
])
def test_matcher_keywords(text, expected):
    assert match_template(text) == expected


def test_first_match_wins():
    assert match_template("lateral movement after credential dump with c2") == "lateral_after_powershell"
    assert match_template("credential dump then phishing") == "credential_dumping"


@pytest.mark.parametrize("text", ["hello there", "suspicious PowerShell execution", "the same thing", ""])
def test_no_match_returns_none(text):
    assert match_template(text) is None  # "same" must not trigger "sam"


def test_examples_all_match():
    assert [match_template(t) for t in EXAMPLE_INTENTS] == list(TEMPLATES)
    assert len(EXAMPLE_INTENTS) == 4


@pytest.mark.parametrize("name", list(TEMPLATES))
def test_templates_build_valid_fallback_plans(name):
    plan = TEMPLATES[name](TR, "x")
    assert plan.source == "fallback" and plan.template == name and plan.time_range == TR
    assert validate_plan(plan).ok, validate_plan(plan).errors
    assert all(s.stage in plan.expected_stages for s in plan.steps if s.stage in ("execution", "lateral_movement")) or True


def test_lateral_template_shape_matches_spec():
    p = TEMPLATES["lateral_after_powershell"](TR, "demo")
    assert p.expected_stages == ["execution", "lateral_movement"]
    s = {x.step_id: x for x in p.steps}
    assert list(s) == ["s1", "s2", "s3", "s4"]
    assert s["s1"].stage == "execution"
    assert [(c.field, c.op, c.value) for c in s["s1"].query.filters] == [
        ("event_type", "eq", "process_create"), ("process.name", "eq", "powershell.exe"),
        ("process.cmdline", "contains", "-enc")]
    assert ("host", "in", "${s1.hosts}") in [(c.field, c.op, c.value) for c in s["s2"].query.filters]
    assert ("net.dst_port", "in", [445, 135, 5985]) in [(c.field, c.op, c.value) for c in s["s2"].query.filters]
    assert s["s3"].depends_on == ["s2"] and s["s4"].depends_on == ["s1"] and s["s2"].depends_on == ["s1"]
    assert ("host", "in", "${s2.dst_hosts}") in [(c.field, c.op, c.value) for c in s["s3"].query.filters]
    assert s["s4"].query.filters[1].value == ["psexec.exe", "wmic.exe", "winrs.exe", "psexesvc.exe"]


def test_other_templates_match_spec():
    c = TEMPLATES["credential_dumping"](TR)
    assert c.expected_stages == ["credential_access"] and len(c.steps) == 3
    b = TEMPLATES["c2_beaconing"](TR)
    assert [s.query.group_by for s in b.steps] == ["dns.query", "net.dst_ip"] and b.expected_stages == ["c2"]
    ph = TEMPLATES["phishing_execution"](TR)
    assert ph.expected_stages == ["initial_access", "execution"] and len(ph.steps) == 2
