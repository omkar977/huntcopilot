"""Hunt service: plans, runs and finding assembly (spec 10.3 and 10.4)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from hc_common.logging import get_logger
from hc_common.schemas import HuntPlan, HuntRun, TimeRange

from agent.pipeline import PlanGenerator

from .approvals import ProposalService
from .assembly import build_findings, candidate_hosts
from .backends import MlError
from .errors import ApiError
from .store import Store

log = get_logger("api")
AUTO_PROPOSAL_MIN_CONFIDENCE = 60.0


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class HuntService:
    """Everything behind POST /v1/hunts, POST /v1/hunts/{plan_id}/run and GET /v1/hunts/{run_id}."""

    def __init__(self, store: Store, backend: Any, ml: Any, lib: Any, generator: PlanGenerator,
                 proposals: ProposalService) -> None:
        self.store, self.backend, self.ml, self.lib = store, backend, ml, lib
        self.generator, self.proposals = generator, proposals

    def default_time_range(self) -> TimeRange:
        """24 hours ending at the newest event timestamp (never the wall clock)."""
        try:
            newest = self.backend.newest_event_ts()
        except Exception as exc:
            raise ApiError("internal", f"could not read the events index ({type(exc).__name__})", status=503)
        if newest is None:
            raise ApiError("not_found", "no events found; load telemetry first (generator) or give a time_range")
        return TimeRange(start=newest - timedelta(hours=24), end=newest)

    def create_plan(self, intent: str, time_range: Optional[TimeRange]) -> HuntPlan:
        tr = time_range or self.default_time_range()
        plan = self.generator.generate(intent, tr)
        log.info("plan generated", extra={"plan_id": plan.plan_id, "source": plan.source, "template": plan.template,
                                          "ok": plan.validation.ok})
        if not plan.validation.ok:
            raise ApiError("validation_failed", "the hunt plan failed validation",
                           {"plan": plan.model_dump(mode="json")})
        self.store.put_plan(plan)
        return plan

    def get_run(self, run_id: str) -> HuntRun:
        run = self.store.get_run(run_id)
        if not run:
            raise ApiError("not_found", f"run {run_id} not found")
        return run

    def run(self, plan_id: str) -> HuntRun:
        plan = self.store.get_plan(plan_id)
        if not plan:
            raise ApiError("not_found", f"plan {plan_id} not found")
        if not plan.validation.ok:
            raise ApiError("validation_failed", "plan is not valid and cannot run", {"errors": plan.validation.errors})
        run = HuntRun(run_id=uuid.uuid4().hex, plan_id=plan_id, started_at=utcnow(), status="running",
                      step_results=[], findings=[])
        try:
            self._execute(plan, run)
            run.status = "completed"
        except (MlError, ApiError) as exc:
            run.status, run.error = "failed", getattr(exc, "message", None) or str(exc)
        except Exception as exc:  # a run never crashes the request; the failure is stored on the run
            log.error("hunt run failed", extra={"run_id": run.run_id, "error": type(exc).__name__})
            run.status, run.error = "failed", f"{type(exc).__name__}: {str(exc)[:200]}"
        run.finished_at = utcnow()
        self.store.put_run(run)
        return run

    def _execute(self, plan: HuntPlan, run: HuntRun) -> None:
        results, evidence = self.lib.run_plan(plan, self.backend.client, run.run_id)
        run.step_results = results
        hosts = candidate_hosts(results, evidence)
        if not hosts:
            return
        windows = self.ml.windows(plan.time_range, hosts, run.run_id)
        alerts = self.backend.alerts_for_hosts(hosts, plan.time_range.start, plan.time_range.end)
        findings = build_findings(run.run_id, plan, evidence, windows, alerts, hosts, self.lib, self.ml,
                                  self.backend.get_events, utcnow())
        for f in findings:
            self.store.put_finding(f)
            self.backend.index_finding(f)
            if f.scores.confidence >= AUTO_PROPOSAL_MIN_CONFIDENCE:
                for act in f.recommended_actions:
                    self.proposals.create(f.finding_id, act.action, act.target, act.rationale, "system")
        run.findings = findings
