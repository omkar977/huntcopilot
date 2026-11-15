"""End to end in mock mode (HC_MOCK_ML + HC_MOCK_HUNT semantics): the master acceptance steps 1, 6, 7, 8."""
import json
from datetime import datetime, timezone

import pytest

from agent.llm import LLMClient
from agent.pipeline import PlanGenerator
from hc_api.approvals import ProposalService
from hc_api.audit import verify_chain
from hc_api.errors import ApiError
from hc_api.export import CaseExporter
from hc_api.hunt_lib import load_hunt_lib, mock_hunt_enabled, mock_ml_enabled
from hc_api.hunts import HuntService
from hc_api.mocks import FixtureBackend, MockMl, load_fixture_events, mock_run_plan
from hc_common.schemas import Finding, HuntRun, TimeRange

DEMO = "Find possible lateral movement after a suspicious PowerShell execution."


@pytest.fixture()
def world(store, audit):
    lib = load_hunt_lib(True)
    backend = FixtureBackend()
    proposals = ProposalService(store, audit)
    hunts = HuntService(store, backend, MockMl(), lib, PlanGenerator(LLMClient(), lib.validate_plan), proposals)
    exporter = CaseExporter(store, audit.path, backend, lib)
    return hunts, proposals, exporter, store, audit, backend


def run_demo(hunts):
    plan = hunts.create_plan(DEMO, None)
    return plan, hunts.run(plan.plan_id)


def test_mock_switches_follow_environment(monkeypatch):
    monkeypatch.delenv("HC_MOCK_ML", raising=False)
    monkeypatch.delenv("HC_MOCK_HUNT", raising=False)
    assert not mock_ml_enabled() and not mock_hunt_enabled()
    assert load_hunt_lib(False).run_source in ("missing", "hc_hunt")
    monkeypatch.setenv("HC_MOCK_ML", "1")
    monkeypatch.setenv("HC_MOCK_HUNT", "1")
    assert mock_ml_enabled() and mock_hunt_enabled()
    assert load_hunt_lib(True).run_source == "mock"


def test_missing_hunt_lib_without_mock_fails_clearly(monkeypatch):
    lib = load_hunt_lib(False)
    if lib.run_source != "missing":
        pytest.skip("hc_hunt is installed")
    with pytest.raises(ApiError) as e:
        lib.run_plan(None, None, "r")
    assert "HC_MOCK_HUNT" in e.value.message


def test_fixture_events_have_no_ground_truth():
    assert all("gt" not in e for e in load_fixture_events())


def test_default_time_range_is_24h_before_newest_event(world):
    hunts = world[0]
    tr = hunts.default_time_range()
    assert tr.end == datetime(2026, 11, 12, 10, 59, 40, tzinfo=timezone.utc)
    assert (tr.end - tr.start).total_seconds() == 86400


def test_step1_demo_plan_is_valid_fallback(world):
    plan = world[0].create_plan(DEMO, None)
    assert plan.source == "fallback" and plan.template == "lateral_after_powershell" and plan.validation.ok


def test_invalid_plan_gives_validation_failed_with_plan_in_details(world):
    hunts = world[0]
    bad = TimeRange(start=datetime(2026, 11, 12, 10, tzinfo=timezone.utc), end=datetime(2026, 11, 12, 9, tzinfo=timezone.utc))
    with pytest.raises(ApiError) as e:
        hunts.create_plan(DEMO, bad)
    assert e.value.code == "validation_failed" and e.value.status == 422
    assert e.value.details["plan"]["validation"]["ok"] is False


def test_run_unknown_plan_is_404(world):
    with pytest.raises(ApiError) as e:
        world[0].run("missing")
    assert e.value.code == "not_found"


def test_step_results_and_top_finding(world):
    hunts = world[0]
    plan, run = run_demo(hunts)
    assert run.status == "completed" and run.finished_at is not None and run.error == ""
    counts = {r.step_id: r.event_count for r in run.step_results}
    assert counts["s1"] >= 1 and counts["s2"] >= 4 and counts["s3"] >= 4 and counts["s4"] >= 2
    s1 = next(r for r in run.step_results if r.step_id == "s1")
    assert "WS-03" in s1.hosts
    top = run.findings[0]
    assert "WS-03" in top.hosts
    assert len(set(top.hosts) - {"WS-03"}) >= 2          # at least 2 lateral hosts
    assert {"FILE-01", "DB-01"} <= set(top.hosts)


def test_finding_has_scores_rationale_and_stages(world):
    top = run_demo(world[0])[1].findings[0]
    s = top.scores
    assert 0 <= s.confidence <= 100 and s.confidence >= 60
    for v in (s.anomaly, s.coverage, s.criticality, s.uncertainty, s.anomaly_if, s.anomaly_seq):
        assert 0 <= v <= 1
    assert top.rationale.startswith("Confidence") and "DB-01" in top.rationale
    assert top.stages_found == ["execution", "lateral_movement"] or set(top.stages_found) >= {"execution", "lateral_movement"}
    assert s.coverage == 1.0
    assert top.technique_ids and top.alert_ids and top.event_ids and "carol" in top.users or "adm_it" in top.users


def test_attack_chain_has_host_to_host_edges(world):
    top = run_demo(world[0])[1].findings[0]
    host_edges = [e for e in top.chain.edges if e.src.startswith("host:") and e.dst.startswith("host:")]
    assert len(host_edges) >= 2 and len(top.chain.nodes) <= 80
    assert {e.kind for e in host_edges} <= {"connected", "authenticated"}


def test_step6_proposals_pending_nothing_executed(world):
    hunts, proposals, _, store, _, _ = world
    _, run = run_demo(hunts)
    top = run.findings[0]
    pend, total = store.list_proposals(finding_id=top.finding_id)
    assert total >= 1 and all(p.status == "pending" for p in pend)
    acts = {(p.action, p.target) for p in pend}
    assert ("isolate_host", "WS-03") in acts
    assert any(a == "block_ip" and t == "203.0.113.50" for a, t in acts)
    assert any(a == "disable_account" and t == "adm_it" for a, t in acts)
    snap = store.state_snapshot()
    assert snap["host_state"] == [] and snap["blocked_ips"] == [] and snap["disabled_accounts"] == []
    assert {(a.action, a.target) for a in top.recommended_actions} == acts


def test_proposals_are_idempotent_across_reruns_of_same_finding(world):
    hunts, proposals, _, store, _, _ = world
    _, run = run_demo(hunts)
    f = run.findings[0]
    before = store.list_proposals(finding_id=f.finding_id)[1]
    for a in f.recommended_actions:
        proposals.create(f.finding_id, a.action, a.target, a.rationale)
    assert store.list_proposals(finding_id=f.finding_id)[1] == before


def test_step7_approve_executes_and_audit_chain_is_valid(world):
    hunts, proposals, _, store, audit, _ = world
    f = run_demo(hunts)[1].findings[0]
    iso = next(p for p in store.list_proposals(finding_id=f.finding_id)[0] if p.action == "isolate_host")
    done = proposals.approve(iso.proposal_id, "soc.lead", True)
    assert done.status == "executed" and done.decided_by == "soc.lead"
    assert store.state_snapshot()["host_state"][0]["host"] == iso.target
    ok, bad = verify_chain(audit.path)
    assert ok and bad is None
    entries = audit.read(500)[0]
    assert {"proposal.created", "proposal.approved", "proposal.executed"} <= {e["action"] for e in entries}


def test_step8_export_json_and_markdown(world):
    hunts, proposals, exporter, store, audit, _ = world
    f = run_demo(hunts)[1].findings[0]
    iso = next(p for p in store.list_proposals(finding_id=f.finding_id)[0] if p.action == "isolate_host")
    proposals.approve(iso.proposal_id, "soc.lead", True)
    case = exporter.case(f.finding_id, "analyst1")
    assert case["case_id"] == f.finding_id and case["analyst"] == "analyst1"
    assert set(case) == {"case_id", "generated_at", "analyst", "hunt", "finding", "proposals", "audit_entries", "notes"}
    assert case["hunt"]["intent_text"] == DEMO and case["hunt"]["plan"]["template"] == "lateral_after_powershell"
    assert case["finding"]["rationale"] == f.rationale
    assert len(case["proposals"]) >= 3 and len(case["audit_entries"]) >= 5
    json.dumps(case)
    Finding.model_validate(case["finding"])
    md = exporter.markdown(case)
    for needle in (f.finding_id, f.rationale):
        assert needle in md
    heads = [ln for ln in md.splitlines() if ln.startswith("## ")]
    assert heads == ["## Summary", "## Timeline", "## Attack chain", "## Confidence breakdown", "## Evidence",
                     "## Recommended and decided actions", "## Audit trail", "## Appendix: CERT-In style fields"]
    assert md.startswith("# Case ") and "```dot" in md and "digraph" in md
    assert "| ts | host | event type | detail |" in md and "powershell.exe" in md
    assert "psexesvc.exe" in md and "executed" in md and "soc.lead" in md


def test_markdown_escapes_pipes_in_cmdline(world):
    from hc_api.export import _cell
    assert "\\|" in _cell("a | b") and "\n" not in _cell("a\nb")


def test_export_unknown_finding_is_404(world):
    with pytest.raises(ApiError) as e:
        world[2].case("nope")
    assert e.value.code == "not_found"


def test_findings_are_stored_and_listed(world):
    hunts, _, _, store, _, _ = world
    f = run_demo(hunts)[1].findings[0]
    items, total = store.list_findings(0, "", 100)
    assert total >= 1 and items[0].finding_id == f.finding_id
    assert items == sorted(items, key=lambda x: -x.scores.confidence)
    assert store.list_findings(99.9)[1] == 0
    assert store.list_findings(0, "DB-01")[1] >= 1 and store.list_findings(0, "WS-07")[1] == 0
    assert store.get_finding(f.finding_id) == f
    run = store.get_run(f.run_id)
    assert isinstance(run, HuntRun) and run.findings[0].finding_id == f.finding_id


def test_run_is_deterministic_for_same_run_id_inputs(world):
    hunts = world[0]
    plan = hunts.create_plan(DEMO, None)
    r1, r2 = hunts.run(plan.plan_id), hunts.run(plan.plan_id)
    assert r1.run_id != r2.run_id
    assert [(f.hosts, f.scores) for f in r1.findings] == [(f.hosts, f.scores) for f in r2.findings]


def test_no_evidence_gives_completed_run_with_zero_findings(world):
    hunts = world[0]
    tr = TimeRange(start=datetime(2026, 1, 1, tzinfo=timezone.utc), end=datetime(2026, 1, 2, tzinfo=timezone.utc))
    plan = hunts.create_plan(DEMO, tr)
    run = hunts.run(plan.plan_id)
    assert run.status == "completed" and run.findings == [] and run.step_results[0].event_count == 0


def test_ml_failure_marks_run_failed(world):
    from hc_api.backends import MlError
    hunts = world[0]

    class Down:
        def windows(self, *a):
            raise MlError("no model is trained yet")

    hunts.ml = Down()
    plan = hunts.create_plan(DEMO, None)
    run = hunts.run(plan.plan_id)
    assert run.status == "failed" and "no model" in run.error and run.findings == []
    assert hunts.get_run(run.run_id).status == "failed"


def test_get_run_unknown(world):
    with pytest.raises(ApiError) as e:
        world[0].get_run("zzz")
    assert e.value.code == "not_found"


def test_mock_run_plan_empty_variable_returns_zero_events(world):
    hunts = world[0]
    plan = hunts.create_plan("credential dump", None)
    results, ev = mock_run_plan(plan, None, "r")
    assert results[0].event_count >= 1 and "DB-01" in results[0].hosts
    # lateral plan over a range with no PowerShell: later steps depending on empty variables return nothing
    tr = TimeRange(start=datetime(2026, 11, 12, 9, 0, tzinfo=timezone.utc), end=datetime(2026, 11, 12, 9, 10, tzinfo=timezone.utc))
    p2 = hunts.create_plan(DEMO, tr)
    res2, _ = mock_run_plan(p2, None, "r")
    assert res2[0].event_count == 0 and res2[1].event_count == 0 and res2[2].event_count == 0


def test_agent_and_api_code_never_read_ground_truth():
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1]
    rx = re.compile(r"""['"]gt['"]|['"]gt\.|\.gt\b|\bgt\.(?:is_malicious|scenario|stage)""")
    for p in (root / "agent").glob("*.py"):
        for line in p.read_text().splitlines():
            assert not rx.search(line), f"{p.name}: {line}"


def test_weak_benign_host_is_split_from_attack_finding(world):
    """WS-08 (benign adm_it script host: one connection, no alerts) must not sit in the attack finding."""
    hunts, _, _, store, _, _ = world
    run = run_demo(hunts)[1]
    attack = run.findings[0]
    assert "WS-08" not in attack.hosts and {"WS-03", "DB-01", "FILE-01"} <= set(attack.hosts)
    solo = [f for f in run.findings if f.hosts == ["WS-08"]]
    assert len(solo) == 1 and solo[0].scores.confidence < attack.scores.confidence
    assert solo[0].recommended_actions == []
    assert not any(a.target == "WS-08" for f in run.findings for a in f.recommended_actions)
    assert all(p.target != "WS-08" for p in store.list_proposals()[0])


def test_every_recommended_action_of_a_confident_finding_becomes_a_proposal(world):
    hunts, _, _, store, _, _ = world
    f = run_demo(hunts)[1].findings[0]
    assert f.scores.confidence >= 60
    props = store.list_proposals(finding_id=f.finding_id)[0]
    assert len(props) == len(f.recommended_actions) >= 3


def test_template_steps_use_size_500():
    from agent.templates import TEMPLATES
    tr = TimeRange(start=datetime(2026, 11, 12, tzinfo=timezone.utc), end=datetime(2026, 11, 13, tzinfo=timezone.utc))
    assert all(st.query.size == 500 for t in TEMPLATES.values() for st in t(tr).steps)
