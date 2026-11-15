"""JSON-lines logging to stdout. Owner: Lead."""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

_STANDARD = set(logging.LogRecord("x", 0, "x", 0, "x", (), None).__dict__.keys()) | {
    "message",
    "asctime",
}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = {
            "ts": now.isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "service": self.service,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    """Return a logger that writes JSON lines to stdout (service name from HC_SERVICE or name)."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter(os.getenv("HC_SERVICE", name)))
        logger.addHandler(handler)
        logger.setLevel(os.getenv("HC_LOG_LEVEL", "INFO").upper())
        logger.propagate = False
    return logger
