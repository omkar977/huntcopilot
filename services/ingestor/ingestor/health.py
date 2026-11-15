"""Health endpoint on port 8301 (standard library HTTP server)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from . import __version__


def make_handler(get_status: Callable[[], dict]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: D102 - silence access logs
            return

        def do_GET(self):  # noqa: N802
            if self.path.split("?")[0] != "/health":
                body, code = {"error": {"code": "not_found", "message": "use /health", "details": {}}}, 404
            else:
                body = {"service": "ingestor", "version": __version__, **get_status()}
                code = 200 if body.get("status") == "ok" else 503
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def start_health_server(get_status: Callable[[], dict], port: int = 8301, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    """Start the health server in a daemon thread and return it (call shutdown() to stop)."""
    server = ThreadingHTTPServer((host, port), make_handler(get_status))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
