"""Hunt plan validator, rules V1 to V10 plus the dst_hosts addendum (spec Sections 5.7 and 10.1). Owner: M2.

validate_plan never raises for a bad plan: every violation becomes one error string that starts with its
rule code (V0 is the field allow-list of Section 5.7).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any, List

from hc_common.constants import ALLOWED_FIELDS, STAGES
from hc_common.schemas import Cond, HuntPlan, HuntStep, ValidationResult

from hc_detect.timeutil import parse_ts

NUMERIC_FIELDS = {"net.dst_port", "auth.logon_type"}
NUMERIC_OPS = {"eq", "neq", "in", "gt", "gte", "lt", "lte"}
TS_OPS = {"gt", "gte", "lt", "lte"}
TEXT_OPS = {"eq", "neq", "in", "contains", "startswith"}
IP_OPS = {"eq", "neq", "in", "startswith"}  # contains cannot be run on an ip typed field
VARIABLE_KINDS = ("hosts", "users", "dst_ips", "dst_hosts")

MAX_STEPS = 6
MAX_FILTERS = 8
MAX_STRING = 200
MAX_RANGE = timedelta(days=7)
STEP_ID = re.compile(r"^s[1-6]$")
VARIABLE = re.compile(r"^\$\{(s[1-6])\.(hosts|users|dst_ips|dst_hosts)\}$")
IP_PREFIX = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){0,3}\.?$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def ops_for_field(field: str) -> set:
    """Operators allowed for a field (V7)."""
    if field in NUMERIC_FIELDS:
        return NUMERIC_OPS
    if field == "ts":
        return TS_OPS
    if field == "net.dst_ip":
        return IP_OPS
    return TEXT_OPS


def _strings_in(value: Any) -> List[str]:
    items = value if isinstance(value, list) else [value]
    return [item for item in items if isinstance(item, str)]


def _check_plan_level(plan: HuntPlan, errors: List[str], warnings: List[str]) -> None:
    count = len(plan.steps)
    if count < 1 or count > MAX_STEPS:  # V1
        errors.append(f"V1: a plan needs 1 to {MAX_STEPS} steps, got {count}")
    start, end = plan.time_range.start, plan.time_range.end
    if start.tzinfo is None or end.tzinfo is None:  # V5
        errors.append("V5: time_range must be timezone-aware")
    elif end <= start:
        errors.append("V5: time_range end must be after start")
    elif end - start > MAX_RANGE:
        errors.append("V5: time_range must not be longer than 7 days")
    for stage in plan.expected_stages:
        if stage not in STAGES:
            warnings.append(f"expected_stages: unknown stage '{stage}' will not count for coverage")


def _check_step_ids(plan: HuntPlan, errors: List[str]) -> None:
    seen: List[str] = []
    for step in plan.steps:
        sid = step.step_id
        if not STEP_ID.match(sid):  # V2
            errors.append(f"V2: step_id '{sid}' must be one of s1 to s6")
        if sid in seen:
            errors.append(f"V2: step_id '{sid}' is used more than once")
        for dep in step.depends_on:  # V3
            if dep not in seen:
                errors.append(f"V3: {sid} depends on '{dep}', which is not an earlier step")
        seen.append(sid)


def _check_value_type(sid: str, cond: Cond, errors: List[str]) -> None:
    field, op, value = cond.field, cond.op, cond.value
    if op == "in" and not isinstance(value, list):
        if not (isinstance(value, str) and VARIABLE.match(value)):
            errors.append(f"V7: {sid} {field}: 'in' needs a list of values or a variable")
        return
    if op != "in" and isinstance(value, list):
        errors.append(f"V7: {sid} {field}: operator '{op}' needs a single value, not a list")
        return
    items = value if isinstance(value, list) else [value]
    if field in NUMERIC_FIELDS:
        for item in items:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                errors.append(f"V7: {sid} {field} needs numeric values")
                return
    elif field == "ts":
        for item in items:
            try:
                parse_ts(item)
            except (ValueError, TypeError):
                errors.append(f"V7: {sid} ts needs ISO 8601 timestamps with a timezone")
                return


def _check_ip_values(sid: str, cond: Cond, errors: List[str]) -> None:
    """net.dst_ip is an ip typed field: eq, neq and in need real addresses, startswith a dotted prefix."""
    for item in _strings_in(cond.value):
        if VARIABLE.match(item):
            continue
        if cond.op == "startswith":
            if not IP_PREFIX.match(item):
                errors.append(f"V7: {sid} net.dst_ip startswith needs a dotted prefix such as 10.10.")
            continue
        try:
            ipaddress.ip_address(item)
        except ValueError:
            errors.append(f"V7: {sid} net.dst_ip value '{item[:40]}' is not an IP address")


def _check_string(sid: str, field: str, text: str, errors: List[str]) -> None:
    if len(text) > MAX_STRING:  # V8
        errors.append(f"V8: {sid} {field}: string longer than {MAX_STRING} characters")
    if text[:1] in ("*", "?"):
        errors.append(f"V8: {sid} {field}: value must not start with a wildcard character")
    if CONTROL.search(text):
        errors.append(f"V8: {sid} {field}: value contains control characters")


def _check_variable(step: HuntStep, cond: Cond, text: str, errors: List[str]) -> None:
    sid = step.step_id
    if "${" not in text:
        return
    match = VARIABLE.match(text)
    if not match:  # V9
        errors.append(f"V9: {sid} {cond.field}: '{text[:40]}' is not a valid variable "
                      f"(use ${{sN.hosts}}, ${{sN.users}}, ${{sN.dst_ips}} or ${{sN.dst_hosts}})")
        return
    if cond.op != "in" or isinstance(cond.value, list):
        errors.append(f"V9: {sid} {cond.field}: a variable is only allowed as the whole value of an 'in' filter")
    if match.group(1) not in step.depends_on:
        errors.append(f"V9: {sid} uses {text} but {match.group(1)} is not listed in depends_on")


def _check_filter(step: HuntStep, cond: Cond, errors: List[str]) -> None:
    sid, field = step.step_id, cond.field
    if field not in ALLOWED_FIELDS:  # V0 allow-list, gt.* is never allowed
        errors.append(f"V0: {sid} field '{field}' is not allowed")
        return
    if cond.op not in ops_for_field(field):  # V7
        errors.append(f"V7: {sid} operator '{cond.op}' is not allowed on field '{field}'")
    _check_value_type(sid, cond, errors)
    if field == "net.dst_ip":
        _check_ip_values(sid, cond, errors)
    for text in _strings_in(cond.value):
        _check_string(sid, field, text, errors)
        _check_variable(step, cond, text, errors)


def _check_step(step: HuntStep, errors: List[str], warnings: List[str]) -> None:
    sid = step.step_id
    if not 1 <= step.query.size <= 500:  # V4
        errors.append(f"V4: {sid} size must be between 1 and 500, got {step.query.size}")
    if len(step.query.filters) > MAX_FILTERS:  # V6
        errors.append(f"V6: {sid} has {len(step.query.filters)} filters, at most {MAX_FILTERS} are allowed")
    if not step.query.filters:
        warnings.append(f"{sid} has no filters and matches every event in the time range")
    for cond in step.query.filters:
        _check_filter(step, cond, errors)
    group = step.query.group_by
    if group is not None and group not in ALLOWED_FIELDS:  # V10
        errors.append(f"V10: {sid} group_by '{group}' is not an allowed field")
    if step.stage and step.stage not in STAGES:
        warnings.append(f"{sid}: unknown stage '{step.stage}' will not count for coverage")


def validate_plan(plan: HuntPlan) -> ValidationResult:
    """Check a plan against V1 to V10 and the field allow-list. Returns ok, errors and warnings."""
    errors: List[str] = []
    warnings: List[str] = []
    _check_plan_level(plan, errors, warnings)
    _check_step_ids(plan, errors)
    for step in plan.steps:
        _check_step(step, errors, warnings)
    return ValidationResult(ok=not errors, errors=errors, warnings=warnings)
