"""Client factories and time helpers. Owner: Lead. Heavy imports are lazy so unit tests need no services."""
from __future__ import annotations

from datetime import datetime, timezone

from .config import get_settings


def get_redis():
    import redis

    return redis.Redis.from_url(get_settings().hc_redis_url, decode_responses=True)


def get_opensearch():
    from opensearchpy import OpenSearch

    return OpenSearch(hosts=[get_settings().hc_opensearch_url])


def events_index_for(ts: datetime) -> str:
    return f"{get_settings().hc_events_index_prefix}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


def events_index_pattern() -> str:
    return f"{get_settings().hc_events_index_prefix}-*"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """UTC ISO 8601 with Z suffix and no microseconds, e.g. 2026-11-12T09:30:00Z."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime is not allowed")
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ts(value: str) -> datetime:
    """Parse an ISO 8601 string (Z or +00:00 suffix) into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return dt.astimezone(timezone.utc)
