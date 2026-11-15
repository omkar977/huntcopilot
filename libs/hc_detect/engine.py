"""Pure, deterministic rule engine (spec Section 5.6 and Appendix J). Owner: M2.

evaluate(rule, events) takes a Rule and a list of event dicts and returns a list of Alert.
The engine never reads the ground-truth key of an event and never does I/O.
"""
from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from hc_common.ids import sha1_hex
from hc_common.schemas import Alert

from .loader import MAX_OPEN_CHAINS, Condition, Rule
from .timeutil import iso, parse_ts

MISSING: Any = object()
Matcher = Callable[[dict], bool]
GroupKey = Tuple[str, ...]


@dataclass(frozen=True)
class Prepared:
    """An event with its parsed timestamp, ready for evaluation."""

    t: float
    dt: datetime
    event_id: str
    event: dict


# ------------------------------------------------------------------ field access and operators
def get_path(event: dict, path: str) -> Any:
    """Return the value at a dotted path, or MISSING when absent or null."""
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return MISSING
    return MISSING if current is None else current


def _as_number(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("bool is not numeric")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return parse_ts(value).timestamp()
    raise ValueError("not comparable")


def _compare_op(op: str, value: Any) -> Callable[[Any], bool]:
    try:
        right = _as_number(value)
    except (ValueError, TypeError):
        return lambda _a: False
    table = {
        "gt": lambda x: x > right,
        "gte": lambda x: x >= right,
        "lt": lambda x: x < right,
        "lte": lambda x: x <= right,
    }
    test = table[op]

    def run(actual: Any) -> bool:
        try:
            return test(_as_number(actual))
        except (ValueError, TypeError):
            return False

    return run


def _scalar_test(op: str, value: Any) -> Callable[[Any], bool]:
    """Build a function testing one scalar field value against the rule value."""
    if op == "eq":
        return lambda a: a == value
    if op == "neq":
        return lambda a: a != value
    if op == "in":
        options = list(value)
        return lambda a: a in options
    if op == "contains":
        needle = str(value).lower()
        return lambda a: needle in str(a).lower()
    if op == "startswith":
        prefix = str(value)
        return lambda a: str(a).startswith(prefix)
    if op == "endswith":
        suffix = str(value)
        return lambda a: str(a).endswith(suffix)
    if op == "regex":
        pattern = re.compile(str(value), re.IGNORECASE)
        return lambda a: pattern.search(str(a)) is not None
    return _compare_op(op, value)


def compile_condition(cond: Condition) -> Matcher:
    """Compile one condition into a function on an event dict.

    A missing field makes the condition false, except exists with value false.
    A list-valued field (such as tags) matches when any element matches (neq: when all differ).
    """
    path = cond.field
    if cond.op == "exists":
        want = bool(cond.value)
        return lambda ev: (get_path(ev, path) is not MISSING) == want
    test = _scalar_test(cond.op, cond.value)
    negate = cond.op == "neq"

    def match(event: dict) -> bool:
        actual = get_path(event, path)
        if actual is MISSING:
            return False
        if isinstance(actual, list):
            if negate:
                return all(test(item) for item in actual)
            return any(test(item) for item in actual)
        return test(actual)

    return match


def compile_all(conds: Iterable[Condition]) -> Matcher:
    """AND of all conditions (true for an empty list)."""
    matchers = [compile_condition(c) for c in conds]
    return lambda ev: all(m(ev) for m in matchers)


def matches(conds: Iterable[Condition], event: dict) -> bool:
    """Convenience wrapper: do all conditions hold for the event?"""
    return compile_all(conds)(event)


# ------------------------------------------------------------------ preparation and grouping
def prepare_events(events: Iterable[dict]) -> List[Prepared]:
    """Parse timestamps and sort by (ts, event_id). Events without a valid ts are skipped."""
    prepared: List[Prepared] = []
    for event in events:
        try:
            dt = parse_ts(event["ts"])
        except (KeyError, ValueError, TypeError):
            continue
        prepared.append(Prepared(dt.timestamp(), dt, str(event.get("event_id", "")), event))
    prepared.sort(key=lambda p: (p.t, p.event_id))
    return prepared


def _group_key(group_by: List[str], event: dict) -> Optional[GroupKey]:
    values: List[str] = []
    for field in group_by:
        value = get_path(event, field)
        if value is MISSING:
            return None
        values.append(str(value))
    return tuple(values)


def _candidate_filter(rule: Rule, conds: List[Condition]) -> Matcher:
    where = compile_all(conds)
    exclusions = [compile_all(group) for group in rule.exclusions]
    return lambda ev: where(ev) and not any(ex(ev) for ex in exclusions)


def _group_candidates(rule: Rule, prepared: List[Prepared], accept: Matcher) -> Dict[GroupKey, List[Prepared]]:
    groups: Dict[GroupKey, List[Prepared]] = {}
    for item in prepared:
        if not accept(item.event):
            continue
        key = _group_key(rule.group_by, item.event)
        if key is None:
            continue
        groups.setdefault(key, []).append(item)
    return groups


# ------------------------------------------------------------------ alert construction
def _make_alert(rule: Rule, key: GroupKey, items: List[Prepared]) -> Alert:
    first, last = items[0], items[-1]
    if "host" in rule.group_by:
        host = key[rule.group_by.index("host")]
    else:
        host = str(last.event.get("host", ""))
    user = str(last.event.get("user", "") or "")
    summary = f"{rule.name}: {len(items)} event(s) on {host}"
    if rule.type == "single":
        cmdline = get_path(last.event, "process.cmdline")
        if cmdline is not MISSING and str(cmdline):
            summary += f" | {str(cmdline)[:120]}"
    return Alert(
        alert_id=sha1_hex(rule.id, ":".join(key), iso(first.dt)),
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        technique_ids=list(rule.mitre.techniques),
        tactics=list(rule.mitre.tactics),
        host=host,
        user=user,
        ts_first=first.dt,
        ts_last=last.dt,
        event_ids=[i.event_id for i in items],
        summary=summary,
        status="new",
        created_at=last.dt,
    )


# ------------------------------------------------------------------ rule types
def _eval_single(rule: Rule, prepared: List[Prepared]) -> List[Alert]:
    accept = _candidate_filter(rule, rule.where)
    alerts: List[Alert] = []
    for key, items in _group_candidates(rule, prepared, accept).items():
        alerts.extend(_make_alert(rule, key, [item]) for item in items)
    return alerts


def _slide(window: "deque[Prepared]", now: float, span: int) -> None:
    while window and now - window[0].t > span:
        window.popleft()


def _threshold_reached(rule: Rule, window: "deque[Prepared]") -> bool:
    if rule.count_gte is not None:
        return len(window) >= rule.count_gte
    seen = set()
    for item in window:
        value = get_path(item.event, rule.distinct_field or "")
        if value is not MISSING:
            seen.add(str(value))
    return len(seen) >= (rule.distinct_gte or 0)


def _eval_threshold(rule: Rule, prepared: List[Prepared]) -> List[Alert]:
    accept = _candidate_filter(rule, rule.where)
    span = rule.window_seconds or 0
    alerts: List[Alert] = []
    for key, items in _group_candidates(rule, prepared, accept).items():
        window: "deque[Prepared]" = deque()
        quiet_until = -math.inf
        for item in items:
            if item.t < quiet_until:
                continue
            window.append(item)
            _slide(window, item.t, span)
            if _threshold_reached(rule, window):
                alerts.append(_make_alert(rule, key, list(window)))
                quiet_until = item.t + span
                window.clear()
    return alerts


def _coefficient_of_variation(window: "deque[Prepared]") -> float:
    times = [i.t for i in window]
    gaps = [b - a for a, b in zip(times, times[1:])]
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return math.inf
    variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return math.sqrt(variance) / mean


def _eval_periodicity(rule: Rule, prepared: List[Prepared]) -> List[Alert]:
    accept = _candidate_filter(rule, rule.where)
    span = rule.window_seconds or 0
    alerts: List[Alert] = []
    for key, items in _group_candidates(rule, prepared, accept).items():
        window: "deque[Prepared]" = deque()
        quiet_until = -math.inf
        for item in items:
            if item.t < quiet_until:
                continue
            window.append(item)
            _slide(window, item.t, span)
            if len(window) >= (rule.min_events or 2) and _coefficient_of_variation(window) <= (rule.max_cv or 0):
                alerts.append(_make_alert(rule, key, list(window)))
                quiet_until = item.t + span
                window.clear()
    return alerts


def _eval_sequence(rule: Rule, prepared: List[Prepared]) -> List[Alert]:
    step_tests = [compile_all(step.where) for step in rule.steps]
    windows = [step.within_seconds or 0 for step in rule.steps]
    not_excluded = _candidate_filter(rule, [])
    groups: Dict[GroupKey, List[Prepared]] = {}
    for item in prepared:
        if not not_excluded(item.event):
            continue
        key = _group_key(rule.group_by, item.event)
        if key is not None:
            groups.setdefault(key, []).append(item)
    alerts: List[Alert] = []
    for key, items in groups.items():
        alerts.extend(_run_chains(rule, key, items, step_tests, windows))
    return alerts


def _run_chains(
    rule: Rule,
    key: GroupKey,
    items: List[Prepared],
    step_tests: List[Matcher],
    windows: List[int],
) -> List[Alert]:
    chains: List[List[Prepared]] = []
    alerts: List[Alert] = []
    last_step = len(step_tests)
    for item in items:
        matched = [i for i, test in enumerate(step_tests) if test(item.event)]
        if not matched and not chains:
            continue
        survivors: List[List[Prepared]] = []
        for chain in chains:
            nxt = len(chain)
            if item.t - chain[-1].t > windows[nxt]:
                continue  # expired: can no longer advance
            if nxt in matched and item.t > chain[-1].t:
                chain = chain + [item]
                if len(chain) == last_step:
                    alerts.append(_make_alert(rule, key, chain))
                    continue
            survivors.append(chain)
        chains = survivors
        if 0 in matched:
            chains.append([item])
            if len(chains) > MAX_OPEN_CHAINS:
                chains.pop(0)
    return alerts


_EVALUATORS = {
    "single": _eval_single,
    "threshold": _eval_threshold,
    "periodicity": _eval_periodicity,
    "sequence": _eval_sequence,
}


# ------------------------------------------------------------------ public API
def _finish(alerts: List[Alert]) -> List[Alert]:
    unique: Dict[str, Alert] = {}
    for alert in alerts:
        unique.setdefault(alert.alert_id, alert)
    return sorted(unique.values(), key=lambda a: (a.ts_first, a.rule_id, a.alert_id))


def evaluate_prepared(rule: Rule, prepared: List[Prepared]) -> List[Alert]:
    """Evaluate one rule on already prepared (parsed and sorted) events."""
    return _finish(_EVALUATORS[rule.type](rule, prepared))


def evaluate(rule: Rule, events: List[dict]) -> List[Alert]:
    """Evaluate one rule on a list of event dicts. Pure, deterministic and idempotent."""
    return evaluate_prepared(rule, prepare_events(events))


def evaluate_rules(rules: Iterable[Rule], events: List[dict]) -> List[Alert]:
    """Evaluate every enabled rule, parsing and sorting the events only once."""
    prepared = prepare_events(events)
    alerts: List[Alert] = []
    for rule in rules:
        if rule.enabled:
            alerts.extend(evaluate_prepared(rule, prepared))
    return sorted(alerts, key=lambda a: (a.ts_first, a.rule_id, a.alert_id))
