"""Hunt plan executor: builds OpenSearch DSL from a validated plan and runs it (spec 5.7, 10.1). Owner: M2.

No raw DSL is ever accepted. Every query is assembled here from allow-listed fields. User text only ever
appears as a term, terms, match_phrase, prefix or escaped wildcard value, and the ground-truth key is always
excluded from _source (and removed again from every returned hit).
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from hc_common.logging import get_logger
from hc_common.schemas import Cond, HuntPlan, HuntStep, StepResult, TimeRange

from hc_detect.timeutil import iso, parse_ts

from .validator import NUMERIC_FIELDS, VARIABLE, validate_plan

MAX_VARIABLE_VALUES = 50
EXCLUDED_SOURCE = ["gt"]
CMDLINE = "process.cmdline"
IP_FIELD = "net.dst_ip"
_WILDCARD_SPECIAL = re.compile(r"([\\*?])")
log = get_logger("hc_hunt.executor")


class PlanValidationError(ValueError):
    """Raised by run_plan when the plan does not pass validate_plan."""

    def __init__(self, errors: List[str]) -> None:
        super().__init__("; ".join(errors) or "invalid plan")
        self.errors = errors


# ------------------------------------------------------------------ DSL building
def escape_wildcard(value: str) -> str:
    """Escape the wildcard metacharacters so that user text is always a literal."""
    return _WILDCARD_SPECIAL.sub(r"\\\1", value)


def _ip_prefix_clause(prefix: str) -> Dict[str, Any]:
    """startswith on an ip field: a dotted prefix becomes a CIDR term (10.10. becomes 10.10.0.0/16)."""
    parts = [p for p in prefix.split(".") if p != ""]
    if not parts or len(parts) > 4:
        raise ValueError("invalid ip prefix")
    if len(parts) == 4 and not prefix.endswith("."):
        return {"term": {IP_FIELD: ".".join(parts)}}
    cidr = ".".join(parts + ["0"] * (4 - len(parts))) + f"/{8 * len(parts)}"
    return {"term": {IP_FIELD: cidr}}


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else [value]


def _keyword_clause(field: str, op: str, value: Any) -> Dict[str, Any]:
    if op in ("eq", "neq"):
        return {"term": {field: str(value)}}
    if op == "in":
        return {"terms": {field: [str(v) for v in _as_list(value)]}}
    if op == "contains":
        return {"wildcard": {field: {"value": f"*{escape_wildcard(str(value))}*", "case_insensitive": True}}}
    if op == "startswith":
        return {"prefix": {field: {"value": str(value), "case_insensitive": True}}}
    raise ValueError(f"operator {op} is not supported on {field}")


def _cmdline_clause(op: str, value: Any) -> Dict[str, Any]:
    if op in ("eq", "neq", "contains"):
        return {"match_phrase": {CMDLINE: str(value)}}
    if op == "in":
        return {"bool": {"should": [{"match_phrase": {CMDLINE: str(v)}} for v in _as_list(value)],
                         "minimum_should_match": 1}}
    if op == "startswith":
        return {"match_phrase_prefix": {CMDLINE: str(value)}}
    raise ValueError(f"operator {op} is not supported on {CMDLINE}")


def _range_clause(field: str, op: str, value: Any) -> Dict[str, Any]:
    if field == "ts":
        value = iso(parse_ts(value))
    return {"range": {field: {op: value}}}


def _numeric_clause(field: str, op: str, value: Any) -> Dict[str, Any]:
    if op in ("eq", "neq"):
        return {"term": {field: value}}
    if op == "in":
        return {"terms": {field: _as_list(value)}}
    return _range_clause(field, op, value)


def _ip_clause(op: str, value: Any) -> Dict[str, Any]:
    if op in ("eq", "neq"):
        return {"term": {IP_FIELD: str(value)}}
    if op == "in":
        return {"terms": {IP_FIELD: [str(v) for v in _as_list(value)]}}
    if op == "startswith":
        return _ip_prefix_clause(str(value))
    raise ValueError(f"operator {op} is not supported on {IP_FIELD}")


def build_clause(field: str, op: str, value: Any) -> Dict[str, Any]:
    """One allow-listed filter as an OpenSearch clause (neq returns the positive clause, see build_query)."""
    if field == "ts":
        return _range_clause(field, op, value)
    if field in NUMERIC_FIELDS:
        return _numeric_clause(field, op, value)
    if field == CMDLINE:
        return _cmdline_clause(op, value)
    if field == IP_FIELD:
        return _ip_clause(op, value)
    return _keyword_clause(field, op, value)


def _resolve(cond: Cond, variables: Dict[str, List[str]]) -> Optional[Any]:
    """Replace a ${sN.kind} variable by its values. Returns None when it resolves to nothing."""
    value = cond.value
    if isinstance(value, str):
        match = VARIABLE.match(value)
        if match:
            found = variables.get(f"{match.group(1)}.{match.group(2)}", [])
            return found[:MAX_VARIABLE_VALUES] or None
    return value


def build_query(step: HuntStep, time_range: TimeRange, variables: Optional[Dict[str, List[str]]] = None,
                start: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """Build the OpenSearch body for one step, or None when a variable resolves to no values.

    start optionally moves the lower bound of the time filter (never earlier than the plan start).
    """
    variables = variables or {}
    must: List[Dict[str, Any]] = []
    must_not: List[Dict[str, Any]] = []
    for cond in step.query.filters:
        value = _resolve(cond, variables)
        if value is None:
            return None
        clause = build_clause(cond.field, cond.op, value)
        (must_not if cond.op == "neq" else must).append(clause)
    must.append({"range": {"ts": {"gte": iso(max(start, time_range.start) if start else time_range.start), "lte": iso(time_range.end)}}})
    boolean: Dict[str, Any] = {"filter": must}
    if must_not:
        boolean["must_not"] = must_not
    body: Dict[str, Any] = {
        "size": step.query.size,
        "sort": [{"ts": "asc"}],
        "_source": {"excludes": list(EXCLUDED_SOURCE)},
        "query": {"bool": boolean},
    }
    group = step.query.group_by
    if group:
        field = f"{CMDLINE}.raw" if group == CMDLINE else group
        body["aggs"] = {"group": {"terms": {"field": field, "size": step.query.size}}}
    return body


# ------------------------------------------------------------------ running a plan
def step_context(events: List[dict]) -> Dict[str, List[str]]:
    """Distinct values later steps can reference: hosts, users, dst_ips and dst_hosts (sorted)."""
    hosts, users, dst_ips, dst_hosts = set(), set(), set(), set()
    for event in events:
        if event.get("host"):
            hosts.add(str(event["host"]))
        if event.get("user"):
            users.add(str(event["user"]))
        net = event.get("net") or {}
        if net.get("dst_ip"):
            dst_ips.add(str(net["dst_ip"]))
        if net.get("dst_host"):
            dst_hosts.add(str(net["dst_host"]))
    return {"hosts": sorted(hosts), "users": sorted(users), "dst_ips": sorted(dst_ips),
            "dst_hosts": sorted(dst_hosts)}


def earliest_dependency_ts(step: HuntStep, evidence: Dict[str, List[dict]]) -> Optional[datetime]:
    """Earliest event time among the steps this step depends on (None when they found nothing)."""
    stamps = []
    for dep in step.depends_on:
        for event in evidence.get(dep, []):
            try:
                stamps.append(parse_ts(event["ts"]))
            except (KeyError, ValueError, TypeError):
                continue
    return min(stamps) if stamps else None


def _index_pattern() -> str:
    try:
        from hc_common.clients import events_index_pattern
        return events_index_pattern()
    except ImportError:
        return os.getenv("HC_EVENTS_INDEX_PREFIX", "hc-events") + "-*"


def _search(os_client: Any, index: str, body: Dict[str, Any]) -> List[dict]:
    response = os_client.search(index=index, body=body)
    events: List[dict] = []
    for hit in response.get("hits", {}).get("hits", []):
        source = dict(hit.get("_source") or {})
        for key in EXCLUDED_SOURCE:
            source.pop(key, None)
        events.append(source)
    return events


def run_plan(plan: HuntPlan, os_client: Any, run_id: str) -> Tuple[List[StepResult], Dict[str, List[dict]]]:
    """Validate and run every step in order. Returns step results and the evidence per step_id.

    Evidence holds at most 500 events per step and never contains the ground-truth key.
    Raises PlanValidationError for an invalid plan.
    """
    verdict = validate_plan(plan)
    if not verdict.ok:
        raise PlanValidationError(verdict.errors)
    index = _index_pattern()
    variables: Dict[str, List[str]] = {}
    results: List[StepResult] = []
    evidence: Dict[str, List[dict]] = {}
    for step in plan.steps:
        started = time.perf_counter()
        body = build_query(step, plan.time_range, variables, earliest_dependency_ts(step, evidence))
        events = [] if body is None else _search(os_client, index, body)[:500]
        context = step_context(events)
        for kind, values in context.items():
            variables[f"{step.step_id}.{kind}"] = values
        duration = int((time.perf_counter() - started) * 1000)
        results.append(StepResult(step_id=step.step_id, event_count=len(events), hosts=context["hosts"],
                                  users=context["users"], dst_ips=context["dst_ips"], duration_ms=duration))
        evidence[step.step_id] = events
        log.info("hunt step done", extra={"run_id": run_id, "step_id": step.step_id, "events": len(events),
                                          "duration_ms": duration})
    return results, evidence
