"""Output sinks: JSONL file and Redis stream hc:telemetry, plus labels.json writing and pacing."""
from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Optional

from hc_common.constants import GROUP_INGESTORS, STREAM_MAXLEN, STREAM_TELEMETRY
from hc_common.logging import get_logger

from .core import to_line

log = get_logger("generator")

BURST_BATCH = 1000
REALTIME_BATCH = 50
BACKLOG_LIMIT = int(STREAM_MAXLEN * 0.8)


def write_jsonl(events: list[dict], path: str) -> int:
    """Write one event per line. Returns the number of lines written."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for ev in events:
            fh.write(to_line(ev) + "\n")
    return len(events)


def default_labels_path() -> str:
    """/data/labels.json when /data is writable (containers), else ./labels.json."""
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data/labels.json"
    return os.path.abspath("labels.json")


def write_labels(labels: dict, path: str) -> str:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(labels, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def backlog(client: Any) -> int:
    """Entries that the ingestor group has not finished: lag plus pending, else the whole stream length."""
    try:
        for g in client.xinfo_groups(STREAM_TELEMETRY):
            name = g.get("name")
            name = name.decode() if isinstance(name, bytes) else name
            if name == GROUP_INGESTORS and g.get("lag") is not None:
                return int(g["lag"]) + int(g.get("pending", 0))
    except Exception:  # noqa: BLE001 - old servers or missing stream: fall back to the stream length
        pass
    try:
        return int(client.xlen(STREAM_TELEMETRY))
    except Exception:  # noqa: BLE001
        return 0


def wait_for_capacity(client: Any, sleep: Callable[[float], None] = time.sleep, max_wait_s: float = 300.0) -> None:
    """Back-pressure so unconsumed entries are never trimmed away by the stream max length."""
    waited = 0.0
    while backlog(client) > BACKLOG_LIMIT:
        if waited >= max_wait_s:
            raise RuntimeError("hc:telemetry backlog is full; is the ingestor running?")
        sleep(0.5)
        waited += 0.5


def push_redis(events: list[dict], client: Any, speed: str = "burst", time_scale: float = 60.0,
               progress: Optional[Callable[[int], None]] = None,
               sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
               should_stop: Optional[Callable[[], bool]] = None) -> int:
    """XADD every event to hc:telemetry (field data holds the Event JSON). Returns the number pushed.

    burst sends as fast as possible. realtime replays the simulated clock divided by time_scale
    (60 means one simulated minute per real second). should_stop is polled between batches (and while
    waiting in realtime mode) so a run can be cancelled; events already sent stay sent.
    """
    batch_size = BURST_BATCH if speed == "burst" else REALTIME_BATCH
    total = len(events)
    if not total:
        return 0
    first_ts = events[0]["ts"]
    from datetime import datetime  # local import keeps module import light

    def seconds_since_first(ev: dict) -> float:
        ts = ev["ts"]
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00")) if isinstance(ts, str) else ts
        f = datetime.fromisoformat(first_ts.replace("Z", "+00:00")) if isinstance(first_ts, str) else first_ts
        return (ts - f).total_seconds()

    wall0 = clock()
    sent = 0
    for i in range(0, total, batch_size):
        if should_stop and should_stop():
            break
        chunk = events[i:i + batch_size]
        if speed == "realtime":
            delay = seconds_since_first(chunk[0]) / max(time_scale, 0.001) - (clock() - wall0)
            while delay > 0 and not (should_stop and should_stop()):
                step = min(delay, 0.5)
                sleep(step)
                delay -= step
            if should_stop and should_stop():
                break
        wait_for_capacity(client, sleep)
        pipe = client.pipeline(transaction=False)
        for ev in chunk:
            pipe.xadd(STREAM_TELEMETRY, {"data": to_line(ev)}, maxlen=STREAM_MAXLEN, approximate=True)
        pipe.execute()
        sent += len(chunk)
        if progress:
            progress(sent)
    return sent
