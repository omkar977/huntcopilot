"""Detector entry point. Run with: python main.py [follow|batch --from T --to T] (owner: M2).

follow (default): evaluates the last 2 hours every 10 seconds and serves the HTTP API on port 8200.
batch: evaluates a range once, prints the summary as JSON and exits.
"""
from __future__ import annotations

import json
import sys
from typing import Any, List, Optional

from detector_service import Detector, build_arg_parser, parse_batch_body, serve, wait_for_store


def main(argv: Optional[List[str]] = None, settings: Any = None, client: Any = None, redis_client: Any = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if settings is None:
        from hc_common.config import get_settings
        settings = get_settings()
    if client is None:
        from hc_common.clients import get_opensearch
        client = get_opensearch()
    if redis_client is None:
        try:
            from hc_common.clients import get_redis
            redis_client = get_redis()
        except Exception:  # noqa: BLE001 - alerts are still stored without the stream
            redis_client = None
    from hc_detect.loader import load_rules
    detector = Detector(load_rules(), client, redis_client,
                        events_pattern=f"{settings.hc_events_index_prefix}-*", alerts_index=settings.hc_alerts_index)
    if args.mode == "batch":
        if not (args.start and args.end):
            print("batch mode needs --from and --to", file=sys.stderr)
            return 2
        body = json.dumps({"start": args.start, "end": args.end}).encode()
        start, end = parse_batch_body(body)
        print(json.dumps(detector.run_batch(start, end)))
        return 0
    if not settings.hc_api_key:
        print("HC_API_KEY is not set", file=sys.stderr)
        return 2
    wait_for_store(client)
    serve(detector, settings.hc_api_key, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
