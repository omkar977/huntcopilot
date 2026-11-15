"""Proposal state machine, simulated executors, audit chain (spec 5.9)."""
import json
import threading

import pytest

from hc_api.approvals import ProposalService, validate_target
from hc_api.audit import GENESIS, AuditLog, compute_hash, verify_chain
from hc_api.errors import ApiError


def mk(svc, action="isolate_host", target="WS-03", finding="f1"):
    return svc.create(finding, action, target, "because")


def test_create_is_pending_and_idempotent(svc, store):
    p1 = mk(svc)
    p2 = mk(svc)
    assert p1.status == "pending" and p1.disruptive and p1.requested_by == "system"
    assert p1.proposal_id == p2.proposal_id
    assert store.list_proposals()[1] == 1
    assert svc.audit.read()[1] == 1  # no second audit entry for the duplicate


def test_nothing_executes_on_create(svc, store):
    mk(svc)
    snap = store.state_snapshot()
    assert snap["host_state"] == [] and snap["blocked_ips"] == []


def test_approve_executes_simulated_isolation(svc, store):
    p = mk(svc)
    done = svc.approve(p.proposal_id, "lead.analyst", True)
    assert done.status == "executed" and done.decided_by == "lead.analyst"
    assert done.executed_at is not None and done.result.startswith("simulated")
    assert store.state_snapshot()["host_state"][0]["host"] == "WS-03"
    assert store.state_snapshot()["host_state"][0]["isolated"] is True


@pytest.mark.parametrize("action,target,table,key", [
    ("block_ip", "203.0.113.50", "blocked_ips", "ip"),
    ("disable_account", "adm_it", "disabled_accounts", "user"),
    ("kill_process", "WS-03:powershell.exe", "killed_processes", "process"),
])
def test_other_executors(svc, store, action, target, table, key):
    p = mk(svc, action, target)
    assert svc.approve(p.proposal_id, "approver", True).status == "executed"
    rows = store.state_snapshot()[table]
    assert len(rows) == 1 and rows[0][key] in target


def test_reject_flow(svc, store):
    p = mk(svc)
    r = svc.reject(p.proposal_id, "approver", "false positive")
    assert r.status == "rejected" and r.decided_by == "approver" and "false positive" in r.result
    assert store.state_snapshot()["host_state"] == []


@pytest.mark.parametrize("first", ["approve", "reject"])
@pytest.mark.parametrize("second", ["approve", "reject"])
def test_no_transition_out_of_final_states(svc, first, second):
    p = mk(svc)
    getattr(svc, first)(p.proposal_id, "approver", True) if first == "approve" else svc.reject(p.proposal_id, "approver")
    with pytest.raises(ApiError) as e:
        svc.approve(p.proposal_id, "approver", True) if second == "approve" else svc.reject(p.proposal_id, "approver")
    assert e.value.code == "conflict" and e.value.status == 409


def test_approval_validation(svc):
    p = mk(svc)
    with pytest.raises(ApiError) as e:
        svc.approve(p.proposal_id, "ab", True)
    assert e.value.code == "invalid_request"
    with pytest.raises(ApiError):
        svc.approve(p.proposal_id, "approver", False)
    with pytest.raises(ApiError):
        svc.reject(p.proposal_id, " a ")
    assert svc.get(p.proposal_id).status == "pending"


def test_unknown_proposal_is_not_found(svc):
    with pytest.raises(ApiError) as e:
        svc.approve("nope", "approver", True)
    assert e.value.code == "not_found"


def test_failed_execution_is_recorded(store, audit):
    def boom(*_):
        raise RuntimeError("disk")

    svc = ProposalService(store, audit, executors={"isolate_host": boom})
    p = svc.create("f", "isolate_host", "WS-01", "x")
    out = svc.approve(p.proposal_id, "approver", True)
    assert out.status == "failed" and "RuntimeError" in out.result
    assert audit.read()[0][-1]["action"] == "proposal.execution_failed"
    assert verify_chain(audit.path) == (True, None)
    with pytest.raises(ApiError):
        svc.approve(p.proposal_id, "approver", True)


def test_concurrent_approvals_only_one_wins(svc):
    p = mk(svc)
    results = []

    def go():
        try:
            results.append(svc.approve(p.proposal_id, "approver", True).status)
        except ApiError as exc:
            results.append(exc.code)

    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("executed") == 1 and results.count("conflict") == 5


@pytest.mark.parametrize("action,target", [
    ("isolate_host", "WS 03"), ("isolate_host", ""), ("block_ip", "not-an-ip"),
    ("kill_process", "powershell.exe"), ("disable_account", "a;b"),
])
def test_bad_targets_rejected(action, target):
    with pytest.raises(ApiError) as e:
        validate_target(action, target)
    assert e.value.code == "invalid_request"


# ------------------------------------------------------------------ audit chain
def test_every_step_writes_a_chained_entry(svc, audit):
    a = mk(svc)
    b = mk(svc, "block_ip", "203.0.113.50")
    svc.approve(a.proposal_id, "approver", True)
    svc.reject(b.proposal_id, "approver", "no")
    entries, total = audit.read(100)
    assert [e["action"] for e in entries] == [
        "proposal.created", "proposal.created", "proposal.approved", "proposal.executed", "proposal.rejected"]
    assert total == 5 and [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert entries[0]["prev_hash"] == GENESIS
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert entries[2]["actor"] == "approver" and entries[3]["actor"] == "system"
    assert verify_chain(audit.path) == (True, None)


def test_hash_is_sha256_of_prev_plus_canonical(audit):
    e = audit.append("a", "x.y", "proposal", "1", None, {"k": 1})
    body = {k: v for k, v in e.items() if k != "hash"}
    import hashlib
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert e["hash"] == hashlib.sha256((GENESIS + canon).encode()).hexdigest() == compute_hash(GENESIS, e)


def _lines(path):
    return open(path, encoding="utf-8").read().splitlines()


def _fill(audit, n=5):
    for i in range(n):
        audit.append("actor", "act", "proposal", f"id{i}", None, {"i": i})


def test_verify_empty_or_missing_is_ok(tmp_path):
    assert verify_chain(str(tmp_path / "none.jsonl")) == (True, None)


def test_tamper_modified_field_detected(audit):
    _fill(audit)
    lines = _lines(audit.path)
    entry = json.loads(lines[2])
    entry["actor"] = "mallory"
    lines[2] = json.dumps(entry, sort_keys=True)
    open(audit.path, "w").write("\n".join(lines) + "\n")
    assert verify_chain(audit.path) == (False, 3)


def test_tamper_deleted_middle_entry_detected(audit):
    _fill(audit)
    lines = _lines(audit.path)
    del lines[1]
    open(audit.path, "w").write("\n".join(lines) + "\n")
    assert verify_chain(audit.path) == (False, 2)


def test_tamper_swapped_entries_detected(audit):
    _fill(audit)
    lines = _lines(audit.path)
    lines[1], lines[2] = lines[2], lines[1]
    open(audit.path, "w").write("\n".join(lines) + "\n")
    assert verify_chain(audit.path)[0] is False


def test_tamper_rehashed_entry_still_breaks_next_link(audit):
    _fill(audit)
    lines = _lines(audit.path)
    e = json.loads(lines[1])
    e["after"] = {"i": 999}
    e["hash"] = compute_hash(e["prev_hash"], e)  # attacker recomputes own hash
    lines[1] = json.dumps(e, sort_keys=True)
    open(audit.path, "w").write("\n".join(lines) + "\n")
    assert verify_chain(audit.path) == (False, 3)


def test_corrupt_line_detected_and_logging_continues(audit):
    _fill(audit, 3)
    with open(audit.path, "a") as fh:
        fh.write("{not json\n")
    assert verify_chain(audit.path) == (False, 4)
    audit.append("a", "still.works", "proposal", "x")  # service keeps working
    assert verify_chain(audit.path)[0] is False


def test_new_instance_continues_chain(tmp_path):
    p = str(tmp_path / "a.jsonl")
    AuditLog(p).append("a", "one", "t", "1")
    AuditLog(p).append("a", "two", "t", "2")
    assert verify_chain(p) == (True, None)
    assert [e["seq"] for e in AuditLog(p).read(10)[0]] == [1, 2]


def test_read_limit_returns_latest(audit):
    _fill(audit, 7)
    entries, total = audit.read(3)
    assert total == 7 and [e["seq"] for e in entries] == [5, 6, 7]
