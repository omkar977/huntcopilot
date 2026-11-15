"""Real backends: OpenSearch (read-only for events and alerts, findings index) and the ml REST client."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import httpx

from hc_common.clients import events_index_pattern, parse_ts
from hc_common.logging import get_logger
from hc_common.schemas import Alert, Finding, ScoreBreakdown, ScoredWindow, TimeRange

log = get_logger("api")
ALERT_FIELDS_EXCLUDE: list[str] = []


class MlError(Exception):
    """The ml service could not answer (down, no model, bad reply)."""


class OpenSearchBackend:
    """Telemetry backend over OpenSearch. `client` is an opensearchpy.OpenSearch (or a compatible fake)."""

    mock = False

    def __init__(self, client: Any, settings: Any) -> None:
        self.client = client
        self.s = settings

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    def newest_event_ts(self) -> Optional[datetime]:
        """Newest event timestamp in the events indices (never the wall clock; the data is synthetic)."""
        body = {"size": 0, "aggs": {"max_ts": {"max": {"field": "ts"}}}}
        res = self.client.search(index=events_index_pattern(), body=body, ignore_unavailable=True)
        agg = (res.get("aggregations") or {}).get("max_ts") or {}
        text = agg.get("value_as_string")
        if text:
            return parse_ts(text)
        if agg.get("value") is not None:
            from datetime import timezone
            return datetime.fromtimestamp(float(agg["value"]) / 1000.0, tz=timezone.utc)
        return None

    def count_events(self) -> int:
        res = self.client.count(index=events_index_pattern(), ignore_unavailable=True)
        return int(res.get("count", 0))

    def get_events(self, ids: list[str]) -> list[dict]:
        """Read events by id. Ground-truth labels are always excluded from _source."""
        if not ids:
            return []
        body = {"size": min(len(ids), 500), "query": {"ids": {"values": list(ids)[:500]}},
                "_source": {"excludes": ["gt"]}, "sort": [{"ts": "asc"}]}
        res = self.client.search(index=events_index_pattern(), body=body, ignore_unavailable=True)
        return [h["_source"] for h in res.get("hits", {}).get("hits", [])]

    def search_alerts(self, status: str = "", rule_id: str = "", host: str = "", limit: int = 100):
        filters = [{"term": {k: v}} for k, v in (("status", status), ("rule_id", rule_id), ("host", host)) if v]
        body = {"size": limit, "track_total_hits": True, "sort": [{"ts_first": "desc"}],
                "query": {"bool": {"filter": filters}} if filters else {"match_all": {}}}
        res = self.client.search(index=self.s.hc_alerts_index, body=body, ignore_unavailable=True)
        hits = res.get("hits", {})
        total = hits.get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        return self._alerts(hits.get("hits", [])), total

    def alerts_for_hosts(self, hosts: list[str], start: datetime, end: datetime) -> list[Alert]:
        body = {"size": 500, "sort": [{"ts_first": "asc"}], "query": {"bool": {"filter": [
            {"terms": {"host": hosts}},
            {"range": {"ts_last": {"gte": start.isoformat()}}},
            {"range": {"ts_first": {"lte": end.isoformat()}}}]}}}
        res = self.client.search(index=self.s.hc_alerts_index, body=body, ignore_unavailable=True)
        return self._alerts(res.get("hits", {}).get("hits", []))

    @staticmethod
    def _alerts(hits: list[dict]) -> list[Alert]:
        out = []
        for h in hits:
            try:
                out.append(Alert.model_validate(h["_source"]))
            except Exception:
                log.warning("skipping malformed alert document", extra={"doc_id": h.get("_id")})
        return out

    def count_alerts(self) -> int:
        res = self.client.count(index=self.s.hc_alerts_index, ignore_unavailable=True)
        return int(res.get("count", 0))

    def index_finding(self, finding: Finding) -> None:
        """Best effort: SQLite stays the source of truth for GET /v1/findings."""
        try:
            self.client.index(index=self.s.hc_findings_index, id=finding.finding_id,
                              body=finding.model_dump(mode="json"), refresh=False)
        except Exception as exc:
            log.warning("could not index finding", extra={"finding_id": finding.finding_id,
                                                           "error": type(exc).__name__})


class HttpMlClient:
    """Client for the ml service (spec 6.2). Sends X-API-Key; never logs it."""

    mock = False

    def __init__(self, base_url: str, api_key: str, timeout_s: float = 30.0) -> None:
        self.base = base_url.rstrip("/")
        self._key = api_key
        self.timeout_s = timeout_s

    def _post(self, path: str, body: dict) -> dict:
        try:
            with httpx.Client(timeout=self.timeout_s) as c:
                resp = c.post(self.base + path, json=body, headers={"X-API-Key": self._key})
        except httpx.HTTPError as exc:
            raise MlError(f"ml service unreachable ({type(exc).__name__})") from None
        if resp.status_code == 409:
            raise MlError("no model is trained yet: POST /v1/train on the ml service first")
        if resp.status_code != 200:
            raise MlError(f"ml service returned HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError:
            raise MlError("ml service returned invalid JSON") from None

    def health(self) -> str:
        try:
            with httpx.Client(timeout=2.0) as c:
                return "ok" if c.get(self.base + "/health").status_code == 200 else "down"
        except httpx.HTTPError:
            return "down"

    def windows(self, tr: TimeRange, hosts: list[str], run_id: str) -> list[ScoredWindow]:
        data = self._post("/v1/windows", {"time_range": tr.model_dump(mode="json"), "hosts": hosts,
                                          "run_id": run_id})
        try:
            return [ScoredWindow.model_validate(w) for w in data["items"]]
        except (KeyError, TypeError, ValueError):
            raise MlError("ml /v1/windows reply does not match ScoredWindow") from None

    def confidence(self, window: ScoredWindow, stages_found: list[str], expected_stages: list[str],
                   hosts: list[str]) -> tuple[ScoreBreakdown, str]:
        data = self._post("/v1/confidence", {"window": window.model_dump(mode="json"),
                                             "stages_found": stages_found, "expected_stages": expected_stages,
                                             "hosts": hosts})
        try:
            return ScoreBreakdown.model_validate(data["scores"]), str(data["rationale"])
        except (KeyError, TypeError, ValueError):
            raise MlError("ml /v1/confidence reply does not match the contract") from None
