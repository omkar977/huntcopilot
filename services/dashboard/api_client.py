"""Dashboard API client (spec 6 and 11.1). Owner: Lead.

One function per api endpoint. Adds X-API-Key, raises ApiError with a readable message,
never prints the key. Pages call only this module (page 7 may call the generator).
List functions return the {items, total} object; use hc_hunt.views.items_of to unwrap.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

TIMEOUT_S = 30.0
HUNT_RUN_TIMEOUT_S = 120.0
_transport: Optional[httpx.BaseTransport] = None  # tests inject httpx.MockTransport


class ApiError(RuntimeError):
    """A readable error for st.error. Never contains the API key."""

    def __init__(self, message: str, status: Optional[int] = None, code: str = "", details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


def api_url() -> str:
    return os.getenv("HC_API_URL", "http://api:8000").rstrip("/")


def _headers() -> Dict[str, str]:
    return {"X-API-Key": os.getenv("HC_API_KEY", "")}


def _clean(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {k: v for k, v in (params or {}).items() if v not in (None, "")}


def _request(method: str, path: str, *, params: Optional[Dict[str, Any]] = None, json: Any = None,
             base: Optional[str] = None, timeout: float = TIMEOUT_S, auth: bool = True) -> Any:
    url = (base or api_url()).rstrip("/") + path
    try:
        with httpx.Client(timeout=timeout, transport=_transport) as client:
            resp = client.request(method, url, params=_clean(params), json=json,
                                  headers=_headers() if auth else {})
    except httpx.TimeoutException as exc:
        raise ApiError(f"Timeout calling {path}") from exc
    except httpx.HTTPError as exc:
        raise ApiError(f"Cannot reach the service for {path} ({type(exc).__name__})") from exc
    if resp.status_code >= 400:
        code, message, details = "", resp.reason_phrase or "error", None
        try:
            err = resp.json().get("error") or {}
            code, message, details = err.get("code", ""), err.get("message") or message, err.get("details")
        except Exception:  # noqa: BLE001 - body is not JSON
            pass
        if resp.status_code == 401:
            message = "Unauthorized: check HC_API_KEY"
        raise ApiError(f"{path}: {message}" + (f" [{code}]" if code else ""), resp.status_code, code, details)
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise ApiError(f"{path}: response is not JSON") from exc


# ---- health -----------------------------------------------------------------
def health() -> dict:
    return _request("GET", "/health", auth=False)


def service_health(base_url: str) -> dict:
    return _request("GET", "/health", base=base_url, auth=False, timeout=3.0)


# ---- hunts ------------------------------------------------------------------
def create_hunt(intent: str, time_range: Optional[dict] = None) -> dict:
    body: Dict[str, Any] = {"intent": intent}
    if time_range:
        body["time_range"] = time_range
    return _request("POST", "/v1/hunts", json=body, timeout=HUNT_RUN_TIMEOUT_S)  # the LLM step can take a while


def run_hunt(plan_id: str) -> dict:
    return _request("POST", f"/v1/hunts/{plan_id}/run", timeout=HUNT_RUN_TIMEOUT_S)


def get_hunt(run_id: str) -> dict:
    return _request("GET", f"/v1/hunts/{run_id}")


# ---- alerts and findings ----------------------------------------------------
def list_alerts(status: Optional[str] = None, rule_id: Optional[str] = None, host: Optional[str] = None,
                limit: int = 100) -> dict:
    return _request("GET", "/v1/alerts", params={"status": status, "rule_id": rule_id, "host": host, "limit": limit})


def list_findings(min_confidence: Optional[float] = None, host: Optional[str] = None, limit: int = 100) -> dict:
    return _request("GET", "/v1/findings", params={"min_confidence": min_confidence, "host": host, "limit": limit})


def get_finding(finding_id: str) -> dict:
    return _request("GET", f"/v1/findings/{finding_id}")


# ---- proposals, audit -------------------------------------------------------
def create_proposal(finding_id: str, action: str, target: str, justification: str) -> dict:
    return _request("POST", "/v1/proposals", json={"finding_id": finding_id, "action": action,
                                                   "target": target, "justification": justification})


def list_proposals(status: Optional[str] = None, limit: int = 100) -> dict:
    return _request("GET", "/v1/proposals", params={"status": status, "limit": limit})


def approve_proposal(proposal_id: str, approver: str, confirm: bool) -> dict:
    return _request("POST", f"/v1/proposals/{proposal_id}/approve", json={"approver": approver, "confirm": confirm})


def reject_proposal(proposal_id: str, approver: str, reason: str) -> dict:
    return _request("POST", f"/v1/proposals/{proposal_id}/reject", json={"approver": approver, "reason": reason})


def list_audit(limit: int = 100) -> dict:
    return _request("GET", "/v1/audit", params={"limit": limit})


def verify_audit() -> dict:
    return _request("GET", "/v1/audit/verify")


# ---- export, state, stats ---------------------------------------------------
def export_case(finding_id: str, fmt: str = "json") -> Any:
    """fmt json returns a dict; fmt md returns the Markdown text."""
    if fmt not in ("json", "md"):
        raise ApiError("format must be json or md")
    url = api_url() + f"/v1/cases/{finding_id}/export"
    if fmt == "json":
        return _request("GET", f"/v1/cases/{finding_id}/export", params={"format": "json"})
    try:
        with httpx.Client(timeout=TIMEOUT_S, transport=_transport) as client:
            resp = client.get(url, params={"format": "md"}, headers=_headers())
    except httpx.HTTPError as exc:
        raise ApiError(f"Cannot reach the api for export ({type(exc).__name__})") from exc
    if resp.status_code >= 400:
        raise ApiError(f"export failed ({resp.status_code})", resp.status_code)
    return resp.text


def get_state() -> dict:
    return _request("GET", "/v1/state")


def get_stats() -> dict:
    return _request("GET", "/v1/stats")


def get_audit(limit: int = 100) -> dict:
    """Alias used by page 4."""
    return list_audit(limit)