"""Error type and error body format (spec Section 3 and 6)."""
from __future__ import annotations

from typing import Any, Optional

ERROR_CODES = (
    "invalid_request",
    "not_found",
    "validation_failed",
    "llm_unavailable",
    "intent_not_understood",
    "conflict",
    "internal",
)

DEFAULT_STATUS = {
    "invalid_request": 422,
    "not_found": 404,
    "validation_failed": 422,
    "llm_unavailable": 503,
    "intent_not_understood": 422,
    "conflict": 409,
    "internal": 500,
}


class ApiError(Exception):
    """Raised by services; the app turns it into the standard error body."""

    def __init__(self, code: str, message: str, details: Any = None, status: Optional[int] = None) -> None:
        super().__init__(message)
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {code}")
        self.code = code
        self.message = message
        self.details = details
        self.status = status or DEFAULT_STATUS[code]

    def body(self) -> dict:
        return error_body(self.code, self.message, self.details)


def error_body(code: str, message: str, details: Any = None) -> dict:
    """Return {"error": {"code", "message", "details"}}."""
    return {"error": {"code": code, "message": message, "details": details}}
