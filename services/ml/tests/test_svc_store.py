"""Query building for the ml service: read-only, range aligned to windows, no labels in feature reads."""
from datetime import datetime, timezone

import ml_store as store


def dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def test_align_range_widens_to_whole_windows():
    s, e = store.align_range(dt("2026-11-12T10:07:30Z"), dt("2026-11-12T11:02:10Z"))
    assert s == dt("2026-11-12T10:00:00Z")
    assert e == dt("2026-11-12T11:14:59Z")


def test_align_range_exact_boundaries_keep_window_complete():
    s, e = store.align_range(dt("2026-11-12T10:00:00Z"), dt("2026-11-12T11:00:00Z"))
    assert s == dt("2026-11-12T10:00:00Z") and e == dt("2026-11-12T10:59:59Z")


def test_feature_query_excludes_ground_truth_fields():
    body = store.build_query(dt("2026-11-12T10:00:00Z"), dt("2026-11-12T11:00:00Z"), ["WS-03"], True)
    src = body["_source"]
    assert not any(f == "gt" or f.startswith("gt.") for f in src)
    flt = body["query"]["bool"]["filter"]
    assert {"terms": {"host": ["WS-03"]}} in flt and {"term": {"tags": "train"}} in flt
    assert flt[0]["range"]["ts"] == {"gte": "2026-11-12T10:00:00Z", "lte": "2026-11-12T11:00:00Z"}
    assert body["sort"][0] == {"ts": "asc"}


def test_label_query_requests_gt_only_for_evaluation():
    assert "gt" in store.LABEL_SOURCE
    assert "gt" not in store.FEATURE_SOURCE


def test_scan_pages_with_search_after_and_respects_limit():
    class Fake:
        def __init__(self):
            self.calls = []

        def search(self, index, body, **kw):
            self.calls.append(dict(body))
            n = len(self.calls)
            hits = [{"_source": {"event_id": f"{n}-{i}"}, "sort": [n, i]} for i in range(body["size"])]
            return {"hits": {"hits": hits if n < 3 else hits[:1]}}

    fake = Fake()
    out = store.fetch_events(fake, "hc-events-*", dt("2026-11-12T10:00:00Z"), dt("2026-11-12T11:00:00Z"))
    assert len(out) == 2 * store.PAGE + 1
    assert "search_after" not in fake.calls[0] and "search_after" in fake.calls[1]
    capped = store.fetch_events(Fake(), "x", dt("2026-11-12T10:00:00Z"), dt("2026-11-12T11:00:00Z"), limit=10)
    assert len(capped) == 10


def test_time_bounds_none_when_empty():
    class Empty:
        def search(self, **kw):
            return {"aggregations": {"lo": {"value": None}, "hi": {"value": None}}}

    assert store.time_bounds(Empty(), "x") is None


def test_time_bounds_parses_millis():
    class One:
        def search(self, **kw):
            return {"aggregations": {"lo": {"value": 1.7e12}, "hi": {"value": 1.7e12 + 3600000}}}

    lo, hi = store.time_bounds(One(), "x")
    assert lo.tzinfo == timezone.utc and (hi - lo).total_seconds() == 3600
