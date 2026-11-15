"""Plan generation: LLM, validate, one repair call, then the deterministic fallback (spec 10.3)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from pydantic import ValidationError

from hc_common.constants import STAGES
from hc_common.schemas import HuntPlan, HuntStep, TimeRange, ValidationResult

from hc_api.errors import ApiError

from .llm import LLMClient, LLMUnavailable, build_messages, build_repair_messages, strip_fences
from .templates import EXAMPLE_INTENTS, TEMPLATES, match_template

Validator = Callable[[HuntPlan], ValidationResult]
MAX_PARSED_STEPS = 20


def _pydantic_messages(exc: ValidationError) -> list[str]:
    """Error text without echoing input values."""
    return [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()][:10]


def stage_errors(plan: HuntPlan) -> list[str]:
    """Extra checks beyond V1..V10: stage names must come from the five allowed stages."""
    errs = [f"expected_stages contains unknown stage '{s}'" for s in plan.expected_stages if s not in STAGES]
    errs += [f"step {st.step_id} has unknown stage '{st.stage}'" for st in plan.steps
             if st.stage and st.stage not in STAGES]
    return errs


class PlanGenerator:
    """Turns analyst text into a HuntPlan. Works with the LLM disabled."""

    def __init__(self, llm: LLMClient, validate: Validator) -> None:
        self.llm = llm
        self.validate = validate

    def generate(self, intent: str, tr: TimeRange) -> HuntPlan:
        intent = intent.strip()
        warnings: list[str] = []
        if self.llm.enabled:
            plan, problem = self._try_llm(intent, tr)
            if plan is not None:
                return plan
            warnings.append(f"LLM plan not used ({problem}); fallback template used")
        return self._fallback(intent, tr, warnings)

    # ------------------------------------------------------------ LLM path
    def _try_llm(self, intent: str, tr: TimeRange) -> tuple[Optional[HuntPlan], str]:
        messages = build_messages(intent)
        try:
            reply = self.llm.complete(messages)
        except LLMUnavailable as exc:
            return None, f"LLM unavailable: {exc}"
        plan, errors = self._parse_and_check(reply, intent, tr)
        if plan is not None:
            return plan, ""
        try:  # exactly ONE repair call, sending only the error messages
            reply2 = self.llm.complete(build_repair_messages(messages, reply, errors))
        except LLMUnavailable as exc:
            return None, f"LLM unavailable during repair: {exc}"
        plan, errors2 = self._parse_and_check(reply2, intent, tr)
        if plan is not None:
            return plan, ""
        return None, "invalid after repair: " + "; ".join((errors2 or errors)[:3])

    def _parse_and_check(self, reply: str, intent: str, tr: TimeRange) -> tuple[Optional[HuntPlan], list[str]]:
        plan, errors = self._parse(reply, intent, tr)
        if plan is None:
            return None, errors
        result = self._check(plan)
        if not result.ok:
            return None, result.errors
        plan.validation = result
        return plan, []

    def _parse(self, reply: str, intent: str, tr: TimeRange) -> tuple[Optional[HuntPlan], list[str]]:
        try:
            data = json.loads(strip_fences(reply))
        except ValueError:
            return None, ["reply is not valid JSON; return only one JSON object"]
        if not isinstance(data, dict):
            return None, ["reply must be one JSON object"]
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            return None, ["steps must be a non-empty list"]
        try:
            steps = [HuntStep.model_validate(s) for s in raw_steps[:MAX_PARSED_STEPS]]
        except ValidationError as exc:
            return None, _pydantic_messages(exc)
        stages = data.get("expected_stages")
        if not isinstance(stages, list) or not all(isinstance(s, str) for s in stages):
            stages = []
        if not stages:
            stages = [s for s in STAGES if any(st.stage == s for st in steps)]
        hypothesis = data.get("hypothesis")
        try:
            plan = HuntPlan(
                plan_id=uuid.uuid4().hex, intent_text=intent,
                hypothesis=hypothesis[:500] if isinstance(hypothesis, str) else "", source="llm", template="",
                time_range=tr, steps=steps, expected_stages=stages,
                created_at=datetime.now(timezone.utc).replace(microsecond=0),
                validation=ValidationResult(ok=True))
        except ValidationError as exc:
            return None, _pydantic_messages(exc)
        return plan, []

    def _check(self, plan: HuntPlan) -> ValidationResult:
        """validate_plan plus the stage checks, merged into one ValidationResult."""
        base = self.validate(plan)
        errors = list(base.errors) + stage_errors(plan)
        return ValidationResult(ok=not errors, errors=errors, warnings=list(base.warnings))

    # ------------------------------------------------------------ fallback path
    def _fallback(self, intent: str, tr: TimeRange, warnings: list[str]) -> HuntPlan:
        name = match_template(intent)
        if name is None:
            raise ApiError("intent_not_understood",
                           "I could not map that request to a hunt. Try one of the example sentences.",
                           {"examples": EXAMPLE_INTENTS})
        plan = TEMPLATES[name](tr, intent)
        result = self._check(plan)
        plan.validation = ValidationResult(ok=result.ok, errors=result.errors,
                                           warnings=list(result.warnings) + warnings)
        return plan
