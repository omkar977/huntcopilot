"""YAML loader and rule validation. Owner: M2."""
import textwrap

import pytest

from hc_detect.loader import RuleLoadError, default_rules_dir, load_rule_file, load_rules, parse_rule

BASE = {"id": "HC-950", "name": "x", "severity": 3, "type": "single",
        "where": [{"field": "host", "op": "eq", "value": "WS-01"}]}


def test_default_rules_dir_holds_ten_rules():
    assert default_rules_dir().is_dir()
    assert len(load_rules()) == 10


def test_parse_minimal_rule_defaults():
    rule = parse_rule(BASE)
    assert rule.enabled and rule.group_by == [] and rule.exclusions == [] and rule.mitre.techniques == []


@pytest.mark.parametrize("patch", [
    {"id": "X-1"}, {"severity": 0}, {"severity": 6}, {"type": "bogus"}, {"name": ""},
    {"where": []}, {"where": [{"field": "host", "op": "like", "value": "x"}]},
    {"where": [{"field": "host", "op": "in", "value": "WS-01"}]},
    {"where": [{"field": "host", "op": "eq", "value": ["a"]}]},
    {"where": [{"field": "host", "op": "exists", "value": "yes"}]},
    {"where": [{"field": "host", "op": "regex", "value": "("}]},
    {"exclusions": [[]]}, {"unknown_key": 1},
])
def test_invalid_rules_rejected(patch):
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, **patch})


def test_threshold_periodicity_sequence_requirements():
    where = BASE["where"]
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "threshold", "where": where, "window_seconds": 10})
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "threshold", "where": where, "window_seconds": 10, "count_gte": 2,
                    "distinct_field": "host", "distinct_gte": 2})
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "periodicity", "where": where, "window_seconds": 10})
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "sequence", "steps": [{"id": "a", "where": where}]})
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "sequence", "steps": [{"id": "a", "where": where}, {"id": "b", "where": where}]})
    with pytest.raises(RuleLoadError):
        parse_rule({**BASE, "type": "sequence", "steps": [{"id": "a", "where": where},
                    {"id": "a", "where": where, "within_seconds": 5}]})


def test_not_a_mapping_and_bad_yaml(tmp_path):
    (tmp_path / "a.yaml").write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        load_rule_file(tmp_path / "a.yaml")
    (tmp_path / "b.yaml").write_text("id: [unclosed", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        load_rule_file(tmp_path / "b.yaml")


def test_duplicate_ids_and_missing_folder(tmp_path):
    text = textwrap.dedent("""
        id: HC-951
        name: dup
        severity: 2
        type: single
        where:
          - {field: host, op: eq, value: WS-01}
    """)
    (tmp_path / "one.yaml").write_text(text, encoding="utf-8")
    (tmp_path / "two.yml").write_text(text, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(tmp_path)
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path / "nope")


def test_enabled_false_rule_is_skipped_by_evaluate_rules():
    from hc_detect.engine import evaluate_rules
    from .helpers import proc
    rule = parse_rule({**BASE, "where": [{"field": "process.name", "op": "eq", "value": "a.exe"}], "enabled": False})
    assert evaluate_rules([rule], [proc(0, "a.exe")]) == []
