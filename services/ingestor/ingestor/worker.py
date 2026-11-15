"""Ingest worker: consumer group `ingestors` on hc:telemetry, bulk index, DLQ, idempotent by event_id.

Messages are acknowledged only after the bulk request succeeded (or after they were copied to hc:dlq).
Transient failures (connection errors, HTTP 429 or 5xx on an item) leave messages pending and they are
retried; permanent failures (invalid message, mapping error) go to hc:dlq.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from hc_common.clients import events_index_for, iso, utcnow
from hc_common.config import Settings, get_settings
from hc_common.constants import GROUP_INGESTORS, STREAM_DLQ, STREAM_TELEMETRY
from hc_common.logging import get_logger
from hc_common.schemas import Event
from pydantic import ValidationError

from .template import TEMPLATE_NAME, build_template

log = get_logger("ingestor")
DLQ_MAXLEN = 100000
TRANSIENT = {429, 500, 502, 503, 504}


@dataclass
class Stats:
    """Counters shown on /health."""

    indexed: int = 0
    dlq: int = 0
    batches: int = 0
    retries: int = 0
    last_error: str = ""
    last_batch_at: str = ""
    started_at: str = field(default_factory=lambda: iso(utcnow()))

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _short(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:500]


def prepare(data: Optional[str], now: datetime) -> tuple[Optional[tuple[str, str, dict]], Optional[str]]:
    """Validate one message. Returns ((index, event_id, doc), None) or (None, error)."""
    if data is None:
        return None, "message has no data field"
    try:
        event = Event.model_validate_json(data)
        for ip in (event.host_ip, event.net.src_ip if event.net else None, event.net.dst_ip if event.net else None):
            if ip is not None:
                ipaddress.ip_address(ip)
    except (ValidationError, ValueError) as exc:
        return None, _short(exc)
    event.ingested_at = now
    doc = event.model_dump(mode="json", exclude_none=True)
    return (events_index_for(event.ts), event.event_id, doc), None


class Ingestor:
    """Reads hc:telemetry in a consumer group and bulk indexes into daily hc-events indices."""

    def __init__(self, redis_client: Any, os_client: Any, settings: Optional[Settings] = None,
                 consumer: str = "ingestor-1", batch_size: int = 500, block_ms: int = 1000,
                 claim_idle_ms: int = 30000, clock: Callable[[], datetime] = utcnow) -> None:
        self.r, self.os = redis_client, os_client
        self.settings = settings or get_settings()
        self.consumer, self.batch_size, self.block_ms = consumer, batch_size, block_ms
        self.claim_idle_ms, self.clock = claim_idle_ms, clock
        self.stats = Stats()
        self._read_pending = True  # on start, first re-read this consumer's unacknowledged messages
        self._transient = False  # set when an item failed with a retryable status
        self._last_claim = 0.0

    # ------------------------------------------------------------ setup
    def ensure_template(self) -> None:
        body = build_template(self.settings.hc_events_index_prefix)
        self.os.indices.put_index_template(name=TEMPLATE_NAME, body=body)

    def ensure_group(self) -> None:
        try:
            self.r.xgroup_create(STREAM_TELEMETRY, GROUP_INGESTORS, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001 - redis raises ResponseError BUSYGROUP when it exists
            if "BUSYGROUP" not in str(exc):
                raise

    def ensure_ready(self) -> None:
        self.ensure_template()
        self.ensure_group()

    # ------------------------------------------------------------ core
    def index_docs(self, docs: list[tuple[str, str, dict]]) -> dict[str, int]:
        """Bulk index (index, id, doc) tuples. Returns {event_id: http status}. Raises on transport errors."""
        if not docs:
            return {}
        body: list[dict] = []
        for index, event_id, doc in docs:
            body.append({"index": {"_index": index, "_id": event_id}})
            body.append(doc)
        resp = self.os.bulk(body=body)
        statuses: dict[str, int] = {}
        for item in resp.get("items", []):
            result = item.get("index") or item.get("create") or {}
            statuses[result.get("_id", "")] = int(result.get("status", 500))
        if not resp.get("errors"):
            return {event_id: 200 for _, event_id, _ in docs}
        return {event_id: statuses.get(event_id, 500) for _, event_id, _ in docs}

    def to_dlq(self, data: Optional[str], error: str) -> None:
        self.r.xadd(STREAM_DLQ, {"data": data or "", "error": error, "ts": iso(self.clock())},
                    maxlen=DLQ_MAXLEN, approximate=True)

    def process(self, messages: list[tuple[str, dict]]) -> list[str]:
        """Handle one batch. Returns the message ids that can be acknowledged."""
        now = self.clock()
        ack: list[str] = []
        docs: list[tuple[str, str, dict]] = []
        owner: dict[str, list[tuple[str, Optional[str]]]] = {}
        for msg_id, fields in messages:
            data = (fields or {}).get("data")  # fields is None if the entry was trimmed while pending
            prepared, error = prepare(data, now)
            if prepared is None:
                self.to_dlq(data, error or "invalid message")
                self.stats.dlq += 1
                ack.append(msg_id)
                continue
            docs.append(prepared)
            owner.setdefault(prepared[1], []).append((msg_id, data))
        statuses = self.index_docs(docs)
        retry = 0
        for _, event_id, _ in docs:
            status = statuses.get(event_id, 500)
            for msg_id, data in owner[event_id]:
                if status < 300:
                    self.stats.indexed += 1
                    ack.append(msg_id)
                elif status in TRANSIENT:
                    retry += 1
                else:
                    self.to_dlq(data, f"opensearch rejected the event with status {status}")
                    self.stats.dlq += 1
                    ack.append(msg_id)
        if retry:
            self.stats.retries += retry
            self._read_pending = True
            self._transient = True
        return ack

    def _claim_stale(self) -> list[tuple[str, dict]]:
        """Take over messages that another (dead) consumer left pending for too long."""
        now = time.monotonic()
        if now - self._last_claim < 30:
            return []
        self._last_claim = now
        try:
            result = self.r.xautoclaim(STREAM_TELEMETRY, GROUP_INGESTORS, self.consumer, self.claim_idle_ms,
                                       start_id="0-0", count=self.batch_size)
        except Exception as exc:  # noqa: BLE001 - optional feature, never stop the worker
            log.warning("xautoclaim failed", extra={"error": _short(exc)})
            return []
        return list(result[1]) if result and len(result) > 1 else []

    def run_once(self) -> int:
        """Read and process one batch. Returns the number of messages read (0 when idle)."""
        read_id = "0" if self._read_pending else ">"
        response = self.r.xreadgroup(GROUP_INGESTORS, self.consumer, {STREAM_TELEMETRY: read_id},
                                     count=self.batch_size, block=None if read_id == "0" else self.block_ms)
        messages = [m for _, batch in (response or []) for m in batch]
        if read_id == "0" and not messages:
            self._read_pending = False  # nothing left to retry: continue with new messages right away
            return self.run_once()
        if read_id == ">" and not messages:
            messages = self._claim_stale()
            if not messages:
                return 0
        self.stats.last_error = ""
        ack = self.process(messages)
        if ack:
            self.r.xack(STREAM_TELEMETRY, GROUP_INGESTORS, *ack)
        self.stats.batches += 1
        self.stats.last_batch_at = iso(self.clock())
        return len(messages)

    def run_forever(self, stop: threading.Event, sleep: Callable[[float], None] = time.sleep) -> None:
        """Loop until stop is set. Dependency errors are logged and retried with back-off (max 10 s)."""
        delay = 0.5
        ready = False
        while not stop.is_set():
            try:
                if not ready:
                    self.ensure_ready()
                    ready = True
                    log.info("ingestor ready", extra={"consumer": self.consumer})
                self.run_once()
                if self._transient:  # OpenSearch pushed back (429 or 5xx): wait before the retry
                    self._transient = False
                    sleep(delay)
                    delay = min(delay * 2, 10.0)
                else:
                    delay = 0.5
            except Exception as exc:  # noqa: BLE001 - keep the worker alive on any dependency error
                self.stats.last_error = _short(exc)
                self._read_pending = True
                log.warning("ingest loop error", extra={"error": self.stats.last_error})
                sleep(delay)
                delay = min(delay * 2, 10.0)

    # ------------------------------------------------------------ files
    def ingest_lines(self, lines: Any, batch_size: int = 1000) -> dict[str, int]:
        """Index events from an iterable of JSON lines (no Redis). Idempotent thanks to the _id."""
        now = self.clock()
        stats = {"indexed": 0, "invalid": 0, "rejected": 0}
        docs: list[tuple[str, str, dict]] = []

        def flush() -> None:
            statuses = self.index_docs(docs)
            for _, event_id, _ in docs:
                if statuses.get(event_id, 500) < 300:
                    stats["indexed"] += 1
                else:
                    stats["rejected"] += 1
            docs.clear()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            prepared, _ = prepare(line, now)
            if prepared is None:
                stats["invalid"] += 1
                continue
            docs.append(prepared)
            if len(docs) >= batch_size:
                flush()
        flush()
        return stats


def wait_until_ready(ingestor: Ingestor, attempts: int = 60, sleep: Callable[[float], None] = time.sleep) -> bool:
    """Used by one-shot commands: wait until OpenSearch accepts the template."""
    for _ in range(attempts):
        try:
            ingestor.ensure_template()
            return True
        except Exception:  # noqa: BLE001
            sleep(2)
    return False


__all__ = ["Ingestor", "Stats", "prepare", "wait_until_ready"]
