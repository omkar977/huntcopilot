"""Tests for api_client (Lead). httpx2 stands in for httpx only when httpx is not installed."""
import sys

try:
    import httpx
except ImportError:  # sandbox without httpx
    import httpx2 as httpx
    sys.modules["httpx"] = httpx

import pytest

import api_client as ac


def mock(handler, monkeypatch):
    monkeypatch.setattr(ac, "_transport", httpx.MockTransport(handler))
    monkeypatch.setenv("HC_API_KEY", "k-test")
    monkeypatch.setenv("HC_API_URL", "http://api.test:8000")


def test_key_header_and_params(monkeypatch):
    seen = {}

    def h(req):
        seen["key"] = req.headers.get("x-api-key")
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"items": [], "total": 0})
    mock(h, monkeypatch)
    ac.list_findings(min_confidence=60, host=None)
    assert seen["key"] == "k-test"
    assert "min_confidence=60" in seen["url"] and "host" not in seen["url"]


def test_names_expected_by_m2_pages():
    for n in ("list_findings", "list_alerts"):
        assert callable(getattr(ac, n))


def test_error_is_readable_and_hides_key(monkeypatch):
    mock(lambda r: httpx.Response(422, json={"error": {"code": "validation_failed", "message": "bad plan",
                                                         "details": {"x": 1}}}), monkeypatch)
    with pytest.raises(ac.ApiError) as e:
        ac.create_hunt("find lateral movement")
    assert e.value.status == 422 and e.value.code == "validation_failed" and "k-test" not in str(e.value)
    assert e.value.details == {"x": 1}


def test_401_and_unreachable(monkeypatch):
    mock(lambda r: httpx.Response(401, text="no"), monkeypatch)
    with pytest.raises(ac.ApiError, match="HC_API_KEY"):
        ac.get_stats()

    def boom(req):
        raise httpx.ConnectError("down")
    mock(boom, monkeypatch)
    with pytest.raises(ac.ApiError, match="Cannot reach"):
        ac.get_stats()


def test_export_md_and_post_bodies(monkeypatch):
    bodies = []

    def h(req):
        bodies.append((req.method, req.url.path, req.content))
        if "export" in req.url.path and req.url.params.get("format") == "md":
            return httpx.Response(200, text="# Case F1")
        return httpx.Response(200, json={"ok": True})
    mock(h, monkeypatch)
    assert ac.export_case("F1", "md") == "# Case F1"
    ac.approve_proposal("P1", "alice", True)
    assert b'"confirm":true' in bodies[-1][2].replace(b" ", b"")
    with pytest.raises(ac.ApiError):
        ac.export_case("F1", "pdf")


def test_get_audit_alias_for_page4(monkeypatch):
    seen = {}

    def h(req):
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"items": [], "total": 0})
    mock(h, monkeypatch)
    ac.get_audit(50)
    assert "/v1/audit" in seen["url"] and "limit=50" in seen["url"]
