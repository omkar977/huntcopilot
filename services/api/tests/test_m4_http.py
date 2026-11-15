"""HTTP layer tests. Need fastapi (and httpx for TestClient); skipped automatically when absent."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from hc_api.app import create_app  # noqa: E402
from hc_common.config import Settings  # noqa: E402

KEY = {"X-API-Key": "test-key"}
DEMO = "Find possible lateral movement after a suspicious PowerShell execution."


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HC_MOCK_ML", "1")
    monkeypatch.setenv("HC_MOCK_HUNT", "1")
    s = Settings(hc_api_key="test-key", hc_db_url="sqlite://", hc_audit_path=str(tmp_path / "audit.jsonl"))
    return TestClient(create_app(s), raise_server_exceptions=False)


def test_health_needs_no_key(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["dependencies"]["llm"] == "disabled"


@pytest.mark.parametrize("path", ["/v1/alerts", "/v1/findings", "/v1/proposals", "/v1/audit", "/v1/state", "/v1/stats"])
def test_unauthorised_is_401(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get(path, headers=KEY).status_code == 200


def test_unauthorised_post_is_401(client):
    assert client.post("/v1/hunts", json={"intent": DEMO}).status_code == 401


def test_error_body_shape(client):
    r = client.get("/v1/findings/nope", headers=KEY)
    assert r.status_code == 404 and set(r.json()["error"]) == {"code", "message", "details"}
    assert r.json()["error"]["code"] == "not_found"
    bad = client.post("/v1/hunts", headers=KEY, json={"intent": "x"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_request"
    odd = client.post("/v1/hunts", headers=KEY, json={"intent": "make me a sandwich"})
    assert odd.status_code == 422 and odd.json()["error"]["code"] == "intent_not_understood"
    assert len(odd.json()["error"]["details"]["examples"]) == 4


def test_full_demo_flow_over_http(client):
    r = client.post("/v1/hunts", headers=KEY, json={"intent": DEMO})
    assert r.status_code == 200
    plan = r.json()
    assert plan["validation"]["ok"] and plan["source"] in ("llm", "fallback")
    run = client.post(f"/v1/hunts/{plan['plan_id']}/run", headers=KEY).json()
    assert run["status"] == "completed" and run["findings"]
    assert client.get(f"/v1/hunts/{run['run_id']}", headers=KEY).json()["run_id"] == run["run_id"]
    top = client.get("/v1/findings", headers=KEY, params={"min_confidence": 60}).json()
    assert top["total"] >= 1
    fid = top["items"][0]["finding_id"]
    assert client.get(f"/v1/findings/{fid}", headers=KEY).status_code == 200
    props = client.get("/v1/proposals", headers=KEY, params={"status": "pending"}).json()["items"]
    assert props and all(p["status"] == "pending" for p in props)
    iso = next(p for p in props if p["action"] == "isolate_host")
    bad = client.post(f"/v1/proposals/{iso['proposal_id']}/approve", headers=KEY,
                      json={"approver": "soc.lead", "confirm": False})
    assert bad.status_code == 422
    ok = client.post(f"/v1/proposals/{iso['proposal_id']}/approve", headers=KEY,
                     json={"approver": "soc.lead", "confirm": True})
    assert ok.status_code == 200 and ok.json()["status"] == "executed"
    again = client.post(f"/v1/proposals/{iso['proposal_id']}/approve", headers=KEY,
                        json={"approver": "soc.lead", "confirm": True})
    assert again.status_code == 409 and again.json()["error"]["code"] == "conflict"
    assert client.get("/v1/audit/verify", headers=KEY).json() == {"ok": True, "first_bad_seq": None}
    assert client.get("/v1/audit", headers=KEY, params={"limit": 5}).json()["total"] >= 3
    state = client.get("/v1/state", headers=KEY).json()
    assert state["host_state"][0]["host"] == iso["target"]
    js = client.get(f"/v1/cases/{fid}/export", headers=KEY, params={"format": "json"}).json()
    md = client.get(f"/v1/cases/{fid}/export", headers=KEY, params={"format": "md"})
    assert js["case_id"] == fid and fid in md.text and js["finding"]["rationale"] in md.text
    assert "attachment" in md.headers["content-disposition"]
    stats = client.get("/v1/stats", headers=KEY).json()
    assert stats["findings"] >= 1 and stats["proposals"] >= 3


def test_manual_proposal_and_reject(client):
    plan = client.post("/v1/hunts", headers=KEY, json={"intent": DEMO}).json()
    run = client.post(f"/v1/hunts/{plan['plan_id']}/run", headers=KEY).json()
    fid = run["findings"][0]["finding_id"]
    missing = client.post("/v1/proposals", headers=KEY, json={
        "finding_id": "none", "action": "block_ip", "target": "203.0.113.9", "justification": "x"})
    assert missing.status_code == 404
    made = client.post("/v1/proposals", headers=KEY, json={
        "finding_id": fid, "action": "block_ip", "target": "203.0.113.9", "justification": "manual"})
    assert made.status_code == 200 and made.json()["status"] == "pending"
    rej = client.post(f"/v1/proposals/{made.json()['proposal_id']}/reject", headers=KEY,
                      json={"approver": "soc.lead", "reason": "no"})
    assert rej.json()["status"] == "rejected"
    assert client.post("/v1/proposals", headers=KEY, json={
        "finding_id": fid, "action": "nuke", "target": "x", "justification": "x"}).status_code == 422


def test_list_limits_and_filters_validated(client):
    assert client.get("/v1/findings", headers=KEY, params={"limit": 501}).status_code == 422
    assert client.get("/v1/proposals", headers=KEY, params={"status": "weird"}).status_code == 422
    assert client.get("/v1/alerts", headers=KEY, params={"rule_id": "HC-001"}).json()["total"] >= 1


def test_oversized_body_rejected(client):
    r = client.post("/v1/hunts", headers=KEY, content=b"x" * 70000)
    assert r.status_code == 413
