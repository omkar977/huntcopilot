"""Pure helpers for dashboard pages 1 (Alert Queue) and 3 (Attack Chain). Owner: M2.

Kept free of Streamlit so the page logic can be unit tested. Pages call only api_client (Lead's module);
call_api finds the right function by trying a few likely names and passes only the arguments it accepts.
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from hc_common.schemas import AttackChain

from .chain import GREY, ORANGE, RED

HIGH, MEDIUM = 80, 60


class ApiClientError(RuntimeError):
    """Raised when api_client has no usable function for a call (message is safe to show)."""


def confidence_label(confidence: float) -> str:
    """80 or more is high, 60 to 79 medium, below 60 low (spec Section 9.3)."""
    if confidence >= HIGH:
        return "high"
    if confidence >= MEDIUM:
        return "medium"
    return "low"


def call_api(module: Any, names: Sequence[str], **kwargs: Any) -> Any:
    """Call the first function of module that exists under one of names, passing only accepted kwargs."""
    for name in names:
        func: Optional[Callable] = getattr(module, name, None)
        if not callable(func):
            continue
        try:
            params = inspect.signature(func).parameters
        except (TypeError, ValueError):
            return func(**kwargs)
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return func(**kwargs)
        return func(**{k: v for k, v in kwargs.items() if k in params})
    raise ApiClientError(f"api_client has no function named {' or '.join(names)}")


def items_of(response: Any) -> List[dict]:
    """List endpoints return {items, total}; also accept a bare list."""
    if isinstance(response, dict):
        return list(response.get("items") or [])
    if isinstance(response, list):
        return response
    return []


def short_ts(value: Any) -> str:
    """2026-11-12T09:30:00Z becomes 2026-11-12 09:30:00."""
    text = str(value or "")
    return text.replace("T", " ").replace("Z", "")[:19]


def _join(values: Optional[Iterable[Any]]) -> str:
    return ", ".join(str(v) for v in (values or []))


def finding_rows(findings: List[dict]) -> List[Dict[str, Any]]:
    """Rows for the ranked findings table, highest confidence first."""
    ranked = sorted(findings, key=lambda f: -float((f.get("scores") or {}).get("confidence", 0)))
    rows = []
    for item in ranked:
        scores = item.get("scores") or {}
        confidence = round(float(scores.get("confidence", 0)), 1)
        rows.append({
            "finding_id": str(item.get("finding_id", "")),
            "confidence": confidence,
            "level": confidence_label(confidence),
            "hosts": _join(item.get("hosts")),
            "users": _join(item.get("users")),
            "stages": _join(item.get("stages_found")),
            "techniques": _join(item.get("technique_ids")),
            "first_seen": short_ts(item.get("ts_first")),
            "last_seen": short_ts(item.get("ts_last")),
        })
    return rows


def finding_option_label(item: dict) -> str:
    """Selectbox label such as 'a1b2c3d4  78.0 medium  WS-03, DB-01'."""
    confidence = round(float((item.get("scores") or {}).get("confidence", 0)), 1)
    return f"{str(item.get('finding_id', ''))[:8]}  {confidence} {confidence_label(confidence)}  {_join(item.get('hosts'))}"


def score_components(finding: dict) -> Dict[str, float]:
    """The four confidence components on a 0..1 scale (certainty is 1 minus uncertainty)."""
    scores = finding.get("scores") or {}
    return {
        "Anomaly (A)": float(scores.get("anomaly", 0)),
        "Evidence coverage (V)": float(scores.get("coverage", 0)),
        "Asset criticality (K)": float(scores.get("criticality", 0)),
        "Certainty (1 - U)": round(1.0 - float(scores.get("uncertainty", 0)), 4),
    }


def feature_rows(finding: dict) -> List[Dict[str, Any]]:
    return [{"feature": f.get("name", ""), "value": f.get("value", 0), "z_score": f.get("z", 0)}
            for f in finding.get("top_features") or []]


def alert_rows(alerts: List[dict]) -> List[Dict[str, Any]]:
    """Rows for the raw rule alert table, newest first."""
    ordered = sorted(alerts, key=lambda a: str(a.get("ts_first", "")), reverse=True)
    return [{
        "ts_first": short_ts(a.get("ts_first")),
        "rule_id": a.get("rule_id", ""),
        "rule_name": a.get("rule_name", ""),
        "severity": a.get("severity", 0),
        "host": a.get("host", ""),
        "user": a.get("user", ""),
        "techniques": _join(a.get("technique_ids")),
        "events": len(a.get("event_ids") or []),
        "status": a.get("status", ""),
        "summary": a.get("summary", ""),
    } for a in ordered]


def chain_of(finding: dict) -> AttackChain:
    """Parse the chain of a finding dict (as returned by the API) into an AttackChain."""
    return AttackChain.model_validate(finding.get("chain") or {"nodes": [], "edges": []})


def edge_rows(chain: AttackChain) -> List[Dict[str, Any]]:
    labels = {n.id: n.label for n in chain.nodes}
    return [{"time": short_ts(e.ts.isoformat()), "kind": e.kind, "from": labels.get(e.src, e.src),
             "to": labels.get(e.dst, e.dst), "event_id": e.event_id} for e in chain.edges]


def host_edge_count(chain: AttackChain) -> int:
    """Number of host-to-host edges (the master acceptance test expects at least 2 for the demo)."""
    return sum(1 for e in chain.edges if e.src.startswith("host:") and e.dst.startswith("host:"))


def legend_rows() -> List[Dict[str, str]]:
    return [
        {"colour": GREY, "meaning": "risk below 0.4"},
        {"colour": ORANGE, "meaning": "risk 0.4 to 0.7"},
        {"colour": RED, "meaning": "risk above 0.7"},
    ]
