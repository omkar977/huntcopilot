"""Command line: python -m ingestor [run] or python -m ingestor ingest-file events.jsonl."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from typing import Optional, Sequence

from hc_common.clients import get_opensearch, get_redis
from hc_common.logging import get_logger

from .health import start_health_server
from .worker import Ingestor, wait_until_ready

log = get_logger("ingestor")


def run_worker(port: int = 8301) -> int:
    ingestor = Ingestor(get_redis(), get_opensearch())
    stop = threading.Event()
    thread = threading.Thread(target=ingestor.run_forever, args=(stop,), daemon=True)

    def status() -> dict:
        alive = thread.is_alive()
        return {"status": "ok" if alive else "failed", **ingestor.stats.as_dict()}

    server = start_health_server(status, port)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    thread.start()
    log.info("ingestor started", extra={"port": port})
    while not stop.is_set() and thread.is_alive():
        time.sleep(0.5)
    stop.set()
    thread.join(timeout=10)
    server.shutdown()
    return 0


def ingest_file(path: str) -> int:
    ingestor = Ingestor(None, get_opensearch())
    if not wait_until_ready(ingestor):
        print("error: OpenSearch is not reachable", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    with open(path, encoding="utf-8") as fh:
        stats = ingestor.ingest_lines(fh)
    seconds = max(time.monotonic() - t0, 1e-6)
    print(json.dumps({**stats, "seconds": round(seconds, 2), "events_per_second": round(stats["indexed"] / seconds)}))
    return 0 if not (stats["invalid"] or stats["rejected"]) else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="ingestor")
    sub = p.add_subparsers(dest="cmd")
    run = sub.add_parser("run", help="run the stream worker (default)")
    run.add_argument("--port", type=int, default=8301)
    f = sub.add_parser("ingest-file", help="index a JSONL file directly (idempotent)")
    f.add_argument("path")
    args = p.parse_args(argv)
    if args.cmd == "ingest-file":
        return ingest_file(args.path)
    return run_worker(getattr(args, "port", 8301))
