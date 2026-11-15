"""Detector service logic: OpenSearch reads, alert upsert, Redis publish, HTTP API (spec 5.5, 6.4, 8). Owner: M2.

The engine lives in libs/hc_detect. Clients are injected so the logic is unit tested with fakes.
The HTTP server uses only the standard library (GET /health, GET /v1/rules, POST /v1/run-batch).
"""
from __future__ import annotations

import argparse
import hmac
import json
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from hc_common.constants import STREAM_ALERTS
from hc_common.logging import get_logger
from hc_common.schemas import Alert
from hc_detect.engine import evaluate_rules
from hc_detect.loader import Rule
from hc_detect.timeutil import iso, parse_ts

log = get_logger("detector")
PAGE_SIZE = 5000
FOLLOW_INTERVAL_S = 10
FOLLOW_WINDOW = timedelta(hours=2)
ALERTS_MAPPING = {"mappings": {"dynamic": True, "properties": {
    "alert_id": {"type": "keyword"}, "rule_id": {"type": "keyword"}, "host": {"type": "keyword"},
    "user": {"type": "keyword"}, "status": {"type": "keyword"}, "severity": {"type": "integer"},
    "ts_first": {"type": "date"}, "ts_last": {"type": "date"}, "created_at": {"type": "date"}}}}


class RequestError(Exception):
    """A client error that maps to an HTTP status and an error code of Section 3."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class Detector:
    """Evaluates the rules over events read from OpenSearch and stores the resulting alerts."""

    def __init__(self, rules: List[Rule], client: Any, redis_client: Any = None,
                 events_pattern: str = "hc-events-*", alerts_index: str = "hc-alerts") -> None:
        self.rules = rules
        self.client = client
        self.redis = redis_client
        self.events_pattern = events_pattern
        self.alerts_index = alerts_index
        self.last_cycle: Optional[str] = None
        self.last_error = ""
        self._lock = threading.Lock()

    # -------------------------------------------------------------- reads
    def fetch_events(self, start: datetime, end: datetime) -> List[dict]:
        """All events with start <= ts <= end, oldest first. The ground-truth key is never fetched."""
        events: List[dict] = []
        after = None
        while True:
            body: Dict[str, Any] = {
                "size": PAGE_SIZE,
                "sort": [{"ts": "asc"}, {"event_id": "asc"}],
                "_source": {"excludes": ["gt"]},
                "query": {"bool": {"filter": [{"range": {"ts": {"gte": iso(start), "lte": iso(end)}}}]}},
            }
            if after is not None:
                body["search_after"] = after
            hits = self.client.search(index=self.events_pattern, body=body).get("hits", {}).get("hits", [])
            events.extend(h["_source"] for h in hits)
            if len(hits) < PAGE_SIZE:
                return events
            after = hits[-1].get("sort")

    def newest_event_ts(self) -> Optional[datetime]:
        """Timestamp of the newest event (the wall clock is never used: the data is synthetic)."""
        body = {"size": 1, "sort": [{"ts": "desc"}], "_source": ["ts"], "query": {"match_all": {}}}
        hits = self.client.search(index=self.events_pattern, body=body).get("hits", {}).get("hits", [])
        return parse_ts(hits[0]["_source"]["ts"]) if hits else None

    # -------------------------------------------------------------- writes
    def ensure_alerts_index(self) -> None:
        try:
            if not self.client.indices.exists(index=self.alerts_index):
                self.client.indices.create(index=self.alerts_index, body=ALERTS_MAPPING)
        except Exception as exc:  # noqa: BLE001 - dynamic mapping still works
            log.warning("could not prepare alerts index", extra={"error": str(exc)})

    def upsert(self, alerts: List[Alert]) -> List[Alert]:
        """Upsert by alert_id. Existing alerts keep their status and created_at. Returns newly created ones."""
        if not alerts:
            return []
        self.ensure_alerts_index()
        lines: List[dict] = []
        for alert in alerts:
            full = json.loads(alert.model_dump_json())
            update = {k: v for k, v in full.items() if k not in ("status", "created_at")}
            lines.append({"update": {"_index": self.alerts_index, "_id": alert.alert_id}})
            lines.append({"doc": update, "upsert": full})
        response = self.client.bulk(body=lines, refresh="wait_for")
        created: List[Alert] = []
        for alert, item in zip(alerts, response.get("items", [])):
            if item.get("update", {}).get("result") == "created":
                created.append(alert)
        return created

    def publish(self, alerts: List[Alert]) -> None:
        if self.redis is None:
            return
        for alert in alerts:
            try:
                self.redis.xadd(STREAM_ALERTS, {"data": alert.model_dump_json()}, maxlen=200000, approximate=True)
            except Exception as exc:  # noqa: BLE001 - publishing must not stop detection
                log.warning("could not publish alert", extra={"error": str(exc)})
                return

    # -------------------------------------------------------------- modes
    def run_batch(self, start: datetime, end: datetime) -> Dict[str, Any]:
        """Evaluate everything in [start, end] and store the alerts (idempotent)."""
        with self._lock:
            events = self.fetch_events(start, end)
            alerts = evaluate_rules(self.rules, events)
            created = self.upsert(alerts)
            self.publish(created)
        per_rule = {rule.id: 0 for rule in self.rules if rule.enabled}
        for alert in alerts:
            per_rule[alert.rule_id] = per_rule.get(alert.rule_id, 0) + 1
        self.last_cycle = iso(end)
        log.info("batch done", extra={"events": len(events), "alerts": len(alerts), "alerts_new": len(created)})
        return {"alerts_created": len(created), "alerts_total": len(alerts), "events_evaluated": len(events),
                "per_rule": per_rule}

    def follow_once(self) -> Optional[Dict[str, Any]]:
        """One follow cycle: re-evaluate the 2 hours before the newest event and upsert the alerts."""
        newest = self.newest_event_ts()
        if newest is None:
            return None
        return self.run_batch(newest - FOLLOW_WINDOW, newest)

    def follow_forever(self, stop: threading.Event, interval: float = FOLLOW_INTERVAL_S) -> None:
        while not stop.is_set():
            try:
                self.follow_once()
                self.last_error = ""
            except Exception as exc:  # noqa: BLE001 - keep the worker alive
                self.last_error = str(exc)[:200]
                log.error("follow cycle failed", extra={"error": self.last_error})
            stop.wait(interval)

    # -------------------------------------------------------------- API payloads
    def rules_payload(self) -> Dict[str, Any]:
        items = [{"id": r.id, "name": r.name, "severity": r.severity, "enabled": r.enabled} for r in self.rules]
        return {"items": items, "total": len(items)}

    def health_payload(self) -> Dict[str, Any]:
        try:
            if hasattr(self.client, "ping") and not self.client.ping():
                raise ConnectionError("ping failed")
            store = "ok"
        except Exception:  # noqa: BLE001
            store = "down"
        return {"status": "ok", "service": "detector", "version": "1.0.0", "rules": len(self.rules),
                "opensearch": store, "last_cycle": self.last_cycle, "last_error": self.last_error}


def parse_batch_body(raw: bytes) -> tuple:
    """Validate the body of POST /v1/run-batch and return (start, end)."""
    try:
        data = json.loads(raw or b"{}")
    except ValueError as exc:
        raise RequestError(400, "invalid_request", "body must be JSON") from exc
    if not isinstance(data, dict) or "start" not in data or "end" not in data:
        raise RequestError(422, "validation_failed", "start and end are required")
    try:
        start, end = parse_ts(data["start"]), parse_ts(data["end"])
    except (ValueError, TypeError) as exc:
        raise RequestError(422, "validation_failed", "start and end must be ISO 8601 with a timezone") from exc
    if end <= start:
        raise RequestError(422, "validation_failed", "end must be after start")
    return start, end


def make_handler(detector: Detector, api_key: str) -> type:
    """Build the request handler class bound to a detector and the API key."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "hc-detector"

        def log_message(self, fmt: str, *args: Any) -> None:  # keep stdout for JSON logs only
            return

        def _send(self, status: int, payload: Dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: int, code: str, message: str) -> None:
            self._send(status, {"error": {"code": code, "message": message, "details": {}}})

        def _authorised(self) -> bool:
            given = self.headers.get("X-API-Key", "")
            return bool(api_key) and hmac.compare_digest(given.encode(), api_key.encode())

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/health":
                return self._send(200, detector.health_payload())
            if not self._authorised():
                return self._error(401, "invalid_request", "missing or wrong X-API-Key")
            if path == "/v1/rules":
                return self._send(200, detector.rules_payload())
            return self._error(404, "not_found", "unknown path")

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if not self._authorised():
                return self._error(401, "invalid_request", "missing or wrong X-API-Key")
            if path != "/v1/run-batch":
                return self._error(404, "not_found", "unknown path")
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 10000)
                start, end = parse_batch_body(self.rfile.read(length))
                self._send(200, detector.run_batch(start, end))
            except RequestError as exc:
                self._error(exc.status, exc.code, exc.message)
            except Exception as exc:  # noqa: BLE001
                log.error("run-batch failed", extra={"error": str(exc)})
                self._error(500, "internal", "batch run failed")

    return Handler


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="detector", description="HuntCopilot detector")
    parser.add_argument("mode", nargs="?", choices=["follow", "batch"], default="follow")
    parser.add_argument("--from", dest="start", help="batch start, ISO 8601 with Z")
    parser.add_argument("--to", dest="end", help="batch end, ISO 8601 with Z")
    parser.add_argument("--port", type=int, default=8200)
    return parser


def serve(detector: Detector, api_key: str, port: int, interval: float = FOLLOW_INTERVAL_S) -> None:
    """Run the follow loop in a thread and the HTTP server in the foreground."""
    stop = threading.Event()
    threading.Thread(target=detector.follow_forever, args=(stop, interval), daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(detector, api_key))  # noqa: S104
    log.info("detector listening", extra={"port": port})
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()


def wait_for_store(client: Any, attempts: int = 30) -> None:
    """Wait until OpenSearch answers (the compose healthcheck normally makes this instant)."""
    for _ in range(attempts):
        try:
            client.info()
            return
        except Exception:  # noqa: BLE001
            time.sleep(2)
