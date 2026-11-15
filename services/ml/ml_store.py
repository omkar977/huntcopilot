"""Read-only access to OpenSearch events for the ml service. Nothing is ever written to the events index."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

WINDOW_S = 15 * 60
# Fields the models may read. Ground truth is requested only by fetch_labelled_events (evaluation).
FEATURE_SOURCE = ["event_id", "ts", "host", "event_type", "tags", "process.name", "process.cmdline",
                  "process.parent_name", "net.dst_ip", "net.dst_port", "net.direction", "net.dst_host",
                  "net.bytes_out", "auth.logon_type", "auth.result", "dns.query", "file.path"]
LABEL_SOURCE = ["event_id", "ts", "host", "event_type", "tags", "process", "net", "auth", "file", "dns", "gt"]
PAGE = 2000


def _z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def align_range(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    """Widen a range to whole 15-minute windows so no window is cut in half."""
    s = start.astimezone(timezone.utc)
    e = end.astimezone(timezone.utc)
    s0 = datetime.fromtimestamp((int(s.timestamp()) // WINDOW_S) * WINDOW_S, tz=timezone.utc)
    e0 = datetime.fromtimestamp(-(-int(e.timestamp()) // WINDOW_S) * WINDOW_S, tz=timezone.utc)
    return s0, e0 - timedelta(seconds=1)


def build_query(start: datetime, end: datetime, hosts: Optional[list[str]] = None, train_only: bool = False,
                source: Optional[list[str]] = None) -> dict:
    """Search body with a ts range, optional host and train filters, sorted by ts."""
    flt: list[dict] = [{"range": {"ts": {"gte": _z(start), "lte": _z(end)}}}]
    if hosts:
        flt.append({"terms": {"host": list(hosts)}})
    if train_only:
        flt.append({"term": {"tags": "train"}})
    return {"query": {"bool": {"filter": flt}}, "sort": [{"ts": "asc"}, {"event_id": "asc"}],
            "_source": source or FEATURE_SOURCE, "size": PAGE}


def _scan(client: Any, index: str, body: dict, limit: int) -> list[dict]:
    out: list[dict] = []
    body = dict(body)
    while len(out) < limit:
        resp = client.search(index=index, body=body, ignore_unavailable=True, allow_no_indices=True)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break
        out.extend(h["_source"] for h in hits)
        body["search_after"] = hits[-1]["sort"]
        if len(hits) < body["size"]:
            break
    return out[:limit]


def fetch_events(client: Any, index: str, start: datetime, end: datetime, hosts: Optional[list[str]] = None,
                 train_only: bool = False, limit: int = 500000) -> list[dict]:
    """Events for scoring or training (no ground truth requested)."""
    s, e = align_range(start, end)
    return _scan(client, index, build_query(s, e, hosts, train_only), limit)


def fetch_labelled_events(client: Any, index: str, start: datetime, end: datetime, limit: int = 500000) -> list[dict]:
    """Events including labels, for POST /v1/evaluate only."""
    s, e = align_range(start, end)
    return _scan(client, index, build_query(s, e, None, False, LABEL_SOURCE), limit)


def time_bounds(client: Any, index: str, train_only: bool = False) -> Optional[tuple[datetime, datetime]]:
    """Earliest and latest ts in the index (optionally for train events); None when empty."""
    q: dict = {"match_all": {}} if not train_only else {"term": {"tags": "train"}}
    body = {"size": 0, "query": q, "aggs": {"lo": {"min": {"field": "ts"}}, "hi": {"max": {"field": "ts"}}}}
    resp = client.search(index=index, body=body, ignore_unavailable=True, allow_no_indices=True)
    aggs = resp.get("aggregations", {})
    lo, hi = aggs.get("lo", {}).get("value"), aggs.get("hi", {}).get("value")
    if lo is None or hi is None:
        return None
    return (datetime.fromtimestamp(lo / 1000, tz=timezone.utc), datetime.fromtimestamp(hi / 1000, tz=timezone.utc))
