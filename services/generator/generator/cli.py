"""Command line: python -m generator run|serve|scenarios."""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Optional, Sequence

from .catalog import PROFILES, SCENARIOS
from .core import GenConfig, build_events
from .sinks import default_labels_path, push_redis, write_jsonl, write_labels


def _scenarios(values: Optional[list[str]]) -> Optional[list[str]]:
    if values is None:
        return None
    out: list[str] = []
    for v in values:
        out.extend(x for x in v.split(",") if x)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="generator", description="HuntCopilot synthetic telemetry generator")
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="generate events")
    run.add_argument("--profile", choices=PROFILES, default="eval")
    run.add_argument("--scenarios", nargs="*", default=None, help=f"any of {SCENARIOS}; default apt_chain for eval")
    run.add_argument("--seed", type=int, default=None, help="default 1001 for benign_train, 2002 for eval")
    run.add_argument("--duration-hours", type=float, default=24.0)
    run.add_argument("--events-per-host-hour", type=float, default=None)
    run.add_argument("--start", default=None, help="UTC start on a whole hour, e.g. 2026-11-12T00:00:00Z")
    run.add_argument("--out", choices=["redis", "jsonl"], default="redis")
    run.add_argument("--jsonl-path", default="events.jsonl")
    run.add_argument("--labels-path", default=None)
    run.add_argument("--speed", choices=["burst", "realtime"], default="burst")
    run.add_argument("--time-scale", type=float, default=60.0, help="realtime only: simulated seconds per second")
    serve = sub.add_parser("serve", help="start the control API on port 8300")
    serve.add_argument("--port", type=int, default=8300)
    sub.add_parser("scenarios", help="print the scenario names")
    return p


def cmd_run(args: argparse.Namespace) -> int:
    cfg = GenConfig(profile=args.profile, scenarios=_scenarios(args.scenarios), seed=args.seed,
                    duration_hours=args.duration_hours, events_per_host_hour=args.events_per_host_hour,
                    start=args.start)
    t0 = time.monotonic()
    events, labels = build_events(cfg)
    built = time.monotonic() - t0
    if args.out == "jsonl":
        write_jsonl(events, args.jsonl_path)
        labels_path = args.labels_path or args.jsonl_path.rsplit(".", 1)[0] + ".labels.json"
        if args.labels_path is None and "/" in args.jsonl_path:
            labels_path = args.jsonl_path.rsplit("/", 1)[0] + "/labels.json"
        elif args.labels_path is None:
            labels_path = "labels.json"
    else:
        from hc_common.clients import get_redis

        labels_path = args.labels_path or default_labels_path()
        push_redis(events, get_redis(), args.speed, args.time_scale)
    write_labels(labels, labels_path)
    total = time.monotonic() - t0
    print(json.dumps({"events": len(events), "malicious": labels["malicious_count"], "out": args.out,
                      "labels": labels_path, "build_seconds": round(built, 2), "total_seconds": round(total, 2)}))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "run":
            return cmd_run(args)
        if args.cmd == "serve":
            from .api import serve

            serve(args.port)
            return 0
        print("\n".join(SCENARIOS))
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
