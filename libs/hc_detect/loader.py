"""Detection rule model, YAML loader and validation (spec Sections 5.6 and 8). Owner: M2."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

OPERATORS = (
    "eq", "neq", "in", "contains", "startswith", "endswith", "regex",
    "gt", "gte", "lt", "lte", "exists",
)
RULE_TYPES = ("single", "sequence", "threshold", "periodicity")
MAX_OPEN_CHAINS = 50


class RuleLoadError(ValueError):
    """Raised when a rule file cannot be read or fails validation."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Condition(_Strict):
    """One condition: dotted field path, operator and value."""

    field: str = Field(min_length=1)
    op: Literal[
        "eq", "neq", "in", "contains", "startswith", "endswith", "regex",
        "gt", "gte", "lt", "lte", "exists",
    ]
    value: Any = None

    @model_validator(mode="after")
    def _check_value(self) -> "Condition":
        value = self.value
        if self.op == "exists":
            if not isinstance(value, bool):
                raise ValueError("exists needs a boolean value")
        elif self.op == "in":
            if not isinstance(value, list) or not value:
                raise ValueError("in needs a non-empty list")
        elif isinstance(value, (list, dict)) or value is None:
            raise ValueError(f"{self.op} needs a scalar value")
        if self.op == "regex":
            try:
                re.compile(str(value), re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
        return self


class Step(_Strict):
    """One step of a sequence rule."""

    id: str = Field(min_length=1)
    where: List[Condition] = Field(min_length=1)
    within_seconds: Optional[int] = Field(default=None, gt=0)


class Mitre(_Strict):
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)


class Rule(_Strict):
    """A validated detection rule (see Section 5.6 for the YAML form)."""

    id: str = Field(pattern=r"^HC-\d{3,}$")
    name: str = Field(min_length=1)
    description: str = ""
    severity: int = Field(ge=1, le=5)
    mitre: Mitre = Field(default_factory=Mitre)
    type: Literal["single", "sequence", "threshold", "periodicity"]
    group_by: List[str] = Field(default_factory=list)
    where: List[Condition] = Field(default_factory=list)
    exclusions: List[List[Condition]] = Field(default_factory=list)
    steps: List[Step] = Field(default_factory=list)
    window_seconds: Optional[int] = Field(default=None, gt=0)
    count_gte: Optional[int] = Field(default=None, gt=0)
    distinct_field: Optional[str] = None
    distinct_gte: Optional[int] = Field(default=None, gt=0)
    min_events: Optional[int] = Field(default=None, ge=2)
    max_cv: Optional[float] = Field(default=None, ge=0)
    enabled: bool = True

    @field_validator("exclusions")
    @classmethod
    def _no_empty_exclusion(cls, value: List[List[Condition]]) -> List[List[Condition]]:
        if any(len(group) == 0 for group in value):
            raise ValueError("an exclusion must hold at least one condition")
        return value

    @model_validator(mode="after")
    def _check_type(self) -> "Rule":
        checker = _TYPE_CHECKS[self.type]
        checker(self)
        return self


def _check_single(rule: Rule) -> None:
    if not rule.where:
        raise ValueError("single rule needs where")


def _check_sequence(rule: Rule) -> None:
    if len(rule.steps) < 2:
        raise ValueError("sequence rule needs at least 2 steps")
    ids = [s.id for s in rule.steps]
    if len(set(ids)) != len(ids):
        raise ValueError("step ids must be unique")
    for step in rule.steps[1:]:
        if step.within_seconds is None:
            raise ValueError(f"step {step.id} needs within_seconds")


def _check_threshold(rule: Rule) -> None:
    if not rule.where:
        raise ValueError("threshold rule needs where")
    if rule.window_seconds is None:
        raise ValueError("threshold rule needs window_seconds")
    by_count = rule.count_gte is not None
    by_distinct = rule.distinct_field is not None and rule.distinct_gte is not None
    if by_count == by_distinct:
        raise ValueError("threshold rule needs either count_gte or distinct_field with distinct_gte")


def _check_periodicity(rule: Rule) -> None:
    if not rule.where:
        raise ValueError("periodicity rule needs where")
    if rule.window_seconds is None or rule.min_events is None or rule.max_cv is None:
        raise ValueError("periodicity rule needs window_seconds, min_events and max_cv")


_TYPE_CHECKS = {
    "single": _check_single,
    "sequence": _check_sequence,
    "threshold": _check_threshold,
    "periodicity": _check_periodicity,
}


def parse_rule(data: Any) -> Rule:
    """Validate a mapping (the parsed YAML) and return a Rule. Raises RuleLoadError."""
    if not isinstance(data, dict):
        raise RuleLoadError("rule file must hold a mapping")
    try:
        return Rule.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        raise RuleLoadError(details) from exc


def load_rule_file(path: "str | Path") -> Rule:
    """Load and validate one YAML rule file."""
    file = Path(path)
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleLoadError(f"{file.name}: cannot read rule ({exc})") from exc
    try:
        return parse_rule(data)
    except RuleLoadError as exc:
        raise RuleLoadError(f"{file.name}: {exc}") from exc


def default_rules_dir() -> Path:
    """Rules folder: HC_RULES_DIR if set, else services/detector/rules next to libs/."""
    env = os.getenv("HC_RULES_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "services" / "detector" / "rules"


def load_rules(directory: "str | Path | None" = None) -> List[Rule]:
    """Load every *.yaml / *.yml rule in a folder, sorted by rule id. Duplicate ids are an error."""
    folder = Path(directory) if directory is not None else default_rules_dir()
    if not folder.is_dir():
        raise RuleLoadError(f"rules folder not found: {folder}")
    files = sorted(list(folder.glob("*.yaml")) + list(folder.glob("*.yml")))
    rules: List[Rule] = []
    seen: dict[str, str] = {}
    for file in files:
        rule = load_rule_file(file)
        if rule.id in seen:
            raise RuleLoadError(f"{file.name}: duplicate rule id {rule.id} (also in {seen[rule.id]})")
        seen[rule.id] = file.name
        rules.append(rule)
    return sorted(rules, key=lambda r: r.id)
