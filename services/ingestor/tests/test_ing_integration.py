"""Pipeline test against real Redis and OpenSearch. Runs only with HC_INTEGRATION=1 (see conftest.py).

Needs the compose stack's redis and opensearch (HC_REDIS_URL and HC_OPENSEARCH_URL point at them).
It uses seed 31337, so its events never collide with the demo data.
"""
import threading
import time

import pytest

pytestmark = pytest.mark.integration


def wait_for(predicate, timeout=90.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.5)
    return False


def test_generator_to_opensearch_with_poison_and_reingest():
    from generator.core import GenConfig, build_events
    from generator.sinks import push_redis
    from hc_common.clients import get_opensearch, get_redis
    from hc_common.constants import STREAM_DLQ, STREAM_TELEMETRY
    from ingestor.worker import Ingestor

    redis_client, os_client = get_redis(), get_opensearch()
    events, _ = build_events(GenConfig(profile="benign_train", seed=31337, duration_hours=3,
                                       events_per_host_hour=50))
    ids = [e["event_id"] for e in events]
    ingestor = Ingestor(redis_client, os_client, consumer="itest-ingestor")
    ingestor.ensure_ready()
    stop = threading.Event()
    worker = threading.Thread(target=ingestor.run_forever, args=(stop,), daemon=True)
    worker.start()

    def indexed() -> int:
        os_client.indices.refresh(index="hc-events-*")
        body = {"query": {"terms": {"event_id": ids}}}
        return os_client.count(index="hc-events-*", body=body)["count"]

    try:
        dlq_before = redis_client.xlen(STREAM_DLQ)
        push_redis(events, redis_client)
        redis_client.xadd(STREAM_TELEMETRY, {"data": "{poison"})
        assert wait_for(lambda: indexed() == len(ids)), "events were not indexed in time"
        assert wait_for(lambda: redis_client.xlen(STREAM_DLQ) == dlq_before + 1)
        push_redis(events, redis_client)  # same ids again: no duplicates
        time.sleep(5)
        assert indexed() == len(ids)
        assert worker.is_alive()
    finally:
        stop.set()
        worker.join(10)
