"""Control API on port 8300 (spec 6.3), built on the standard library HTTP server.

All endpoints except GET /health need the X-API-Key header equal to HC_API_KEY.
Errors use {"error": {"code", "message", "details"}}.
"""
from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from hc_common.config import require_api_key
from hc_common.logging import get_logger

from . import __version__
from .catalog import SCENARIOS
from .core import GenConfig
from .runner import Busy, Runner

log = get_logger("generator")
MAX_BODY = 64 * 1024
RUN_FIELDS = {"profile", "scenarios", "seed", "duration_hours", "events_per_host_hour", "speed", "start",
              "time_scale"}


def make_handler(runner: Runner, api_key: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "hc-generator"

        def log_message(self, fmt: str, *args: Any) -> None:  # keep access logs out of stdout noise
            return

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, code: int, name: str, message: str, details: Optional[dict] = None) -> None:
            self._send(code, {"error": {"code": name, "message": message, "details": details or {}}})

        def _authorised(self) -> bool:
            given = self.headers.get("X-API-Key", "")
            return bool(api_key) and hmac.compare_digest(given.encode(), api_key.encode())

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            if path == "/health":
                return self._send(200, {"status": "ok", "service": "generator", "version": __version__})
            if not self._authorised():
                return self._error(401, "invalid_request", "missing or wrong X-API-Key")
            if path == "/v1/scenarios":
                return self._send(200, {"items": SCENARIOS, "total": len(SCENARIOS)})
            if path == "/v1/status":
                return self._send(200, runner.status())
            return self._error(404, "not_found", f"no route {path}")

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            if path != "/v1/run":
                return self._error(404, "not_found", f"no route {path}")
            if not self._authorised():
                return self._error(401, "invalid_request", "missing or wrong X-API-Key")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_BODY:
                    return self._error(400, "invalid_request", "body too large")
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
                unknown = set(body) - RUN_FIELDS
                if unknown:
                    raise ValueError(f"unknown fields {sorted(unknown)}")
                cfg = GenConfig(
                    profile=body.get("profile", "eval"),
                    scenarios=body.get("scenarios"),
                    seed=body.get("seed"),
                    duration_hours=body.get("duration_hours", 24),
                    events_per_host_hour=body.get("events_per_host_hour"),
                    start=body.get("start"),
                )
                run_id = runner.start(cfg, body.get("speed", "burst"), float(body.get("time_scale", 60.0)))
            except Busy as exc:
                return self._error(409, "conflict", str(exc))
            except (ValueError, TypeError) as exc:
                return self._error(400, "invalid_request", str(exc))
            self._send(202, {"run_id": run_id})

    return Handler


def create_server(runner: Runner, api_key: str, host: str = "0.0.0.0", port: int = 8300) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(runner, api_key))


def serve(port: int = 8300) -> None:
    """Start the control API (blocks). Needs HC_API_KEY."""
    from hc_common.clients import get_redis

    key = require_api_key()
    server = create_server(Runner(redis_factory=get_redis), key, port=port)
    log.info("generator control API listening", extra={"port": port})
    try:
        server.serve_forever()
    finally:
        server.server_close()
