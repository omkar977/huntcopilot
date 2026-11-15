"""Small timestamp helpers with no third-party dependencies (Python 3.10 safe). Owner: M2."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

_FRACTION = re.compile(r"\.(\d+)")


def parse_ts(value: Any) -> datetime:
    """Parse an ISO 8601 string (Z, +00:00 or other offset) or an aware datetime into aware UTC.

    Raises ValueError for naive or unparsable values.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("timestamp must carry a timezone")
        return value.astimezone(timezone.utc)
    if not isinstance(value, str):
        raise ValueError(f"unsupported timestamp type: {type(value).__name__}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    match = _FRACTION.search(text)
    if match:
        fraction = match.group(1)[:6].ljust(6, "0")
        text = text[: match.start()] + "." + fraction + text[match.end():]
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return parsed.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    """UTC ISO 8601 with Z suffix and no microseconds, e.g. 2026-11-12T09:30:00Z."""
    if value.tzinfo is None:
        raise ValueError("naive datetime is not allowed")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
