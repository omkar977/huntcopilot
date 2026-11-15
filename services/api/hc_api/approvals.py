"""Proposal state machine and simulated executors (spec Section 5.9).

Executors are SIMULATIONS: they only write rows of the local SQLite state tables. No code path here
touches a real system (spec Section 1.9).
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from hc_common.schemas import Proposal

from .audit import AuditLog
from .errors import ApiError
from .store import Store

NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
PROCESS_TARGET_RE = re.compile(r"^([A-Za-z0-9_.\-]{1,64}):([A-Za-z0-9_.\-]{1,64})$")

# pending -> approved -> executed | failed ; pending -> rejected. Nothing else.
TRANSITIONS = {
    "pending": {"approved", "rejected"},
    "approved": {"executed", "failed"},
    "executed": set(),
    "failed": set(),
    "rejected": set(),
}


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def validate_target(action: str, target: str) -> str:
    """Return the cleaned target or raise ApiError(invalid_request)."""
    t = target.strip()
    if action in ("isolate_host", "disable_account"):
        ok = bool(NAME_RE.match(t))
    elif action == "block_ip":
        try:
            ipaddress.ip_address(t)
            ok = True
        except ValueError:
            ok = False
    elif action == "kill_process":
        ok = bool(PROCESS_TARGET_RE.match(t))
    else:
        ok = False
    if not ok:
        hint = "HOST:process.exe" if action == "kill_process" else "a valid name or address"
        raise ApiError("invalid_request", f"invalid target for {action}: expected {hint}")
    return t


def _exec_isolate(store: Store, target: str, when: str) -> str:
    store.sim_isolate(target, when)
    return f"simulated: host {target} marked isolated"


def _exec_block_ip(store: Store, target: str, when: str) -> str:
    store.sim_block_ip(target, when)
    return f"simulated: ip {target} added to blocklist"


def _exec_disable(store: Store, target: str, when: str) -> str:
    store.sim_disable_account(target, when)
    return f"simulated: account {target} marked disabled"


def _exec_kill(store: Store, target: str, when: str) -> str:
    m = PROCESS_TARGET_RE.match(target)
    if not m:
        raise ValueError("kill_process target must be HOST:process")
    store.sim_kill_process(m.group(1), m.group(2), when)
    return f"simulated: process {m.group(2)} on {m.group(1)} marked killed"


EXECUTORS: dict[str, Callable[[Store, str, str], str]] = {
    "isolate_host": _exec_isolate,
    "block_ip": _exec_block_ip,
    "disable_account": _exec_disable,
    "kill_process": _exec_kill,
}


class ProposalService:
    """Create, approve, reject and (simulated) execute proposals; every step is audited."""

    def __init__(self, store: Store, audit: AuditLog, executors: Optional[dict] = None) -> None:
        self.store = store
        self.audit = audit
        self.executors = executors or EXECUTORS

    def create(self, finding_id: str, action: str, target: str, justification: str,
               requested_by: str = "system") -> Proposal:
        """Create a pending proposal. Idempotent per (finding_id, action, target)."""
        target = validate_target(action, target)
        existing = self.store.find_proposal(finding_id, action, target)
        if existing:
            return existing
        prop = Proposal(proposal_id=uuid.uuid4().hex, finding_id=finding_id, action=action, target=target,
                        justification=justification, disruptive=True, status="pending",
                        requested_by=requested_by, requested_at=now())
        if not self.store.insert_proposal(prop):  # lost a race with an identical create
            return self.store.find_proposal(finding_id, action, target) or prop
        self.audit.append(requested_by, "proposal.created", "proposal", prop.proposal_id, None,
                          prop.model_dump(mode="json"))
        return prop

    def get(self, proposal_id: str) -> Proposal:
        prop = self.store.get_proposal(proposal_id)
        if not prop:
            raise ApiError("not_found", f"proposal {proposal_id} not found")
        return prop

    def _move(self, prop: Proposal, new_status: str, **changes) -> Proposal:
        """Compare-and-set transition; raises conflict if the proposal is not in the expected state."""
        if new_status not in TRANSITIONS[prop.status]:
            raise ApiError("conflict", f"cannot move proposal from {prop.status} to {new_status}")
        updated = prop.model_copy(update={"status": new_status, **changes})
        if not self.store.update_proposal_if(updated, prop.status):
            raise ApiError("conflict", "proposal was changed by another request; reload and retry")
        return updated

    def approve(self, proposal_id: str, approver: str, confirm: bool) -> Proposal:
        """pending -> approved -> executed (or failed). Needs a named approver and confirm true."""
        approver = approver.strip()
        if len(approver) < 3:
            raise ApiError("invalid_request", "approver must have at least 3 characters")
        if confirm is not True:
            raise ApiError("invalid_request", "confirm must be true to approve")
        prop = self.get(proposal_id)
        if prop.status != "pending":
            raise ApiError("conflict", f"proposal is {prop.status}, only pending proposals can be approved")
        before = prop.model_dump(mode="json")
        approved = self._move(prop, "approved", decided_by=approver, decided_at=now())
        self.audit.append(approver, "proposal.approved", "proposal", proposal_id, before,
                          approved.model_dump(mode="json"))
        return self._execute(approved)

    def _execute(self, prop: Proposal) -> Proposal:
        before = prop.model_dump(mode="json")
        when = now()
        stamp = when.isoformat().replace("+00:00", "Z")
        try:
            result = self.executors[prop.action](self.store, prop.target, stamp)
            final = self._move(prop, "executed", executed_at=when, result=result)
            action = "proposal.executed"
        except ApiError:
            raise
        except Exception as exc:  # simulated executor failed; record it, never crash the request
            final = self._move(prop, "failed", executed_at=when, result=f"execution failed: {type(exc).__name__}")
            action = "proposal.execution_failed"
        self.audit.append("system", action, "proposal", prop.proposal_id, before, final.model_dump(mode="json"))
        return final

    def reject(self, proposal_id: str, approver: str, reason: str = "") -> Proposal:
        """pending -> rejected."""
        approver = approver.strip()
        if len(approver) < 3:
            raise ApiError("invalid_request", "approver must have at least 3 characters")
        prop = self.get(proposal_id)
        if prop.status != "pending":
            raise ApiError("conflict", f"proposal is {prop.status}, only pending proposals can be rejected")
        before = prop.model_dump(mode="json")
        rejected = self._move(prop, "rejected", decided_by=approver, decided_at=now(),
                              result=f"rejected: {reason}" if reason else "rejected")
        self.audit.append(approver, "proposal.rejected", "proposal", proposal_id, before,
                          rejected.model_dump(mode="json"))
        return rejected
