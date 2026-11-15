"""Case export as JSON and Markdown (spec Section 5.10)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from hc_common.schemas import AttackChain, Finding

from .audit import read_entries
from .errors import ApiError
from .hunts import utcnow
from .store import Store

NOTES = [
    "All telemetry is synthetic; no personal data is processed.",
    "Containment actions are simulations. Nothing was executed on a real system.",
    "Confidence is a transparent score (anomaly, coverage, criticality, uncertainty), not a verdict.",
]
MAX_TIMELINE_EVENTS = 200
DETAIL_LEN = 140


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _cell(text: Any, limit: int = DETAIL_LEN) -> str:
    s = " ".join(str(text).split())
    s = s[:limit] + "..." if len(s) > limit else s
    return s.replace("|", "\\|")


def confidence_label(confidence: float) -> str:
    return "high" if confidence >= 80 else "medium" if confidence >= 60 else "low"


def event_detail(ev: dict) -> str:
    """One-line description of an event for the timeline."""
    et = ev.get("event_type")
    if et == "process_create" and ev.get("process"):
        p = ev["process"]
        return f"{p.get('cmdline') or p.get('name')} (parent {p.get('parent_name') or 'n/a'})"
    if et == "network_conn" and ev.get("net"):
        n = ev["net"]
        return f"{n.get('src_ip')} -> {n.get('dst_ip')}:{n.get('dst_port')} ({n.get('direction')})"
    if et == "auth" and ev.get("auth"):
        a = ev["auth"]
        return f"logon type {a.get('logon_type')} {a.get('result')} as {a.get('target_user')} from {a.get('src_host') or 'n/a'}"
    if et == "file_create" and ev.get("file"):
        return f"{ev['file'].get('action', 'create')} {ev['file'].get('path')}"
    if et == "dns_query" and ev.get("dns"):
        return f"{ev['dns'].get('query')} -> {ev['dns'].get('answer') or 'n/a'}"
    return ""


class CaseExporter:
    """Builds the case document for a finding from the store, the audit file and the telemetry backend."""

    def __init__(self, store: Store, audit_path: str, backend: Any, lib: Any) -> None:
        self.store, self.audit_path, self.backend, self.lib = store, audit_path, backend, lib

    def case(self, finding_id: str, analyst: str = "") -> dict:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ApiError("not_found", f"finding {finding_id} not found")
        run = self.store.get_run(finding.run_id)
        plan = self.store.get_plan(run.plan_id) if run else None
        proposals, _ = self.store.list_proposals(finding_id=finding_id, limit=500)
        ids = {finding_id} | {p.proposal_id for p in proposals}
        audit = [e for e in read_entries(self.audit_path) if e.get("object_id") in ids]
        return {
            "case_id": finding_id,
            "generated_at": _iso(utcnow()),
            "analyst": analyst,
            "hunt": {"intent_text": plan.intent_text if plan else "",
                     "plan": plan.model_dump(mode="json") if plan else None},
            "finding": finding.model_dump(mode="json"),
            "proposals": [p.model_dump(mode="json") for p in proposals],
            "audit_entries": audit,
            "notes": list(NOTES),
        }

    def timeline_events(self, finding: Finding) -> list[dict]:
        try:
            events = self.backend.get_events(finding.event_ids[:MAX_TIMELINE_EVENTS])
        except Exception:
            events = []
        return sorted(events, key=lambda e: (str(e.get("ts")), str(e.get("event_id"))))

    def markdown(self, case: dict, events: Optional[list[dict]] = None) -> str:
        finding = Finding.model_validate(case["finding"])
        if events is None:
            events = self.timeline_events(finding)
        return render_markdown(case, finding, events, self.lib.chain_to_dot(finding.chain))


def _timeline(finding: Finding, events: list[dict]) -> list[str]:
    rows = ["| ts | host | event type | detail |", "| --- | --- | --- | --- |"]
    if events:
        for e in events:
            rows.append(f"| {_cell(e.get('ts'))} | {_cell(e.get('host'))} | {_cell(e.get('event_type'))} | "
                        f"{_cell(event_detail(e))} |")
    else:  # evidence bodies unavailable: fall back to the chain edges
        for edge in finding.chain.edges:
            rows.append(f"| {_iso(edge.ts)} | {_cell(edge.src)} | {edge.kind} | {_cell(edge.src)} -> {_cell(edge.dst)} |")
    return rows


def _edge_list(chain: AttackChain) -> list[str]:
    if not chain.edges:
        return ["- (no edges)"]
    return [f"- {_iso(e.ts)}  {e.src} -> {e.dst} ({e.kind})" for e in chain.edges]


def render_markdown(case: dict, finding: Finding, events: list[dict], dot: str) -> str:
    s = finding.scores
    label = confidence_label(s.confidence)
    hosts = ", ".join(finding.hosts)
    out = [f"# Case {finding.finding_id[:12]}: activity on {hosts}", ""]
    out += ["## Summary", "",
            f"- Case id: `{finding.finding_id}`",
            f"- Generated at: {case['generated_at']}   Analyst: {case.get('analyst') or 'n/a'}",
            f"- Hunt request: {case['hunt']['intent_text'] or 'n/a'}",
            f"- Hosts: {hosts}   Users: {', '.join(finding.users) or 'n/a'}",
            f"- Window: {_iso(finding.ts_first)} to {_iso(finding.ts_last)}",
            f"- Confidence: {s.confidence:.0f} of 100 ({label})",
            f"- Stages found: {', '.join(finding.stages_found) or 'none'}",
            f"- Techniques: {', '.join(finding.technique_ids) or 'none'}", ""]
    out += ["## Timeline", ""] + _timeline(finding, events) + [""]
    out += ["## Attack chain", "", "```dot", dot, "```", ""] + _edge_list(finding.chain) + [""]
    out += ["## Confidence breakdown", "",
            "| component | value |", "| --- | --- |",
            f"| anomaly (A) | {s.anomaly:.2f} (isolation forest {s.anomaly_if:.2f}, sequence {s.anomaly_seq:.2f}) |",
            f"| coverage (V) | {s.coverage:.2f} |", f"| criticality (K) | {s.criticality:.2f} |",
            f"| uncertainty (U) | {s.uncertainty:.2f} |", f"| confidence | {s.confidence:.1f} |", "",
            finding.rationale, ""]
    out += ["## Evidence", "", f"Event ids ({len(finding.event_ids)}):", ""]
    out += [f"- `{i}`" for i in finding.event_ids[:MAX_TIMELINE_EVENTS]] or ["- none"]
    out += ["", f"Alert ids ({len(finding.alert_ids)}):", ""] + ([f"- `{i}`" for i in finding.alert_ids] or ["- none"])
    out += ["", "## Recommended and decided actions", ""]
    out += _actions(finding, case["proposals"]) + [""]
    out += ["## Audit trail", ""] + _audit(case["audit_entries"]) + [""]
    out += _appendix(finding, case["proposals"], label)
    return "\n".join(out).rstrip() + "\n"


def _actions(finding: Finding, proposals: list[dict]) -> list[str]:
    if not proposals and not finding.recommended_actions:
        return ["- none"]
    rows = ["| action | target | status | decided by | justification |", "| --- | --- | --- | --- | --- |"]
    for p in proposals:
        rows.append(f"| {p['action']} | {_cell(p['target'])} | {p['status']} | {p.get('decided_by') or '-'} | "
                    f"{_cell(p['justification'], 200)} |")
    if not proposals:
        for a in finding.recommended_actions:
            rows.append(f"| {a.action} | {_cell(a.target)} | recommended (no proposal) | - | {_cell(a.rationale, 200)} |")
    return rows


def _audit(entries: list[dict]) -> list[str]:
    if not entries:
        return ["No audit entries for this case yet."]
    rows = ["| seq | ts | actor | action | object | hash |", "| --- | --- | --- | --- | --- | --- |"]
    for e in entries:
        rows.append(f"| {e.get('seq')} | {e.get('ts')} | {_cell(e.get('actor'))} | {_cell(e.get('action'))} | "
                    f"{_cell(e.get('object_id'))} | `{str(e.get('hash'))[:16]}` |")
    return rows


def _appendix(finding: Finding, proposals: list[dict], label: str) -> list[str]:
    taken = [f"{p['action']} {p['target']}" for p in proposals if p["status"] == "executed"]
    return ["## Appendix: CERT-In style fields", "",
            f"- Incident time: {_iso(finding.ts_first)}",
            f"- Affected systems: {', '.join(finding.hosts)}",
            "- Incident type: targeted intrusion with lateral movement (synthetic exercise data)",
            f"- Severity: {label}",
            f"- Actions taken: {'; '.join(taken) if taken else 'none executed (simulated actions only)'}"]
