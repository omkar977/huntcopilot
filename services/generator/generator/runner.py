"""Background run management for the control API (one run at a time)."""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Optional

from hc_common.logging import get_logger

from .core import GenConfig, build_events
from .sinks import default_labels_path, push_redis, write_labels

log = get_logger("generator")


class Busy(Exception):
    """Raised when a run is already in progress."""


class Runner:
    """Starts generation runs in a thread and reports their status (idle, running, done, stopped)."""

    def __init__(self, redis_factory: Optional[Callable[[], Any]] = None,
                 labels_path: Optional[Callable[[], str]] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._redis_factory = redis_factory
        self._labels_path = labels_path or default_labels_path
        self._sleep = sleep
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {"state": "idle", "produced": 0, "run_id": "", "total": 0, "error": "",
                                       "labels_path": ""}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def stop(self) -> bool:
        """Ask the running run to stop. Returns True when a run was running. Sent events are not removed."""
        with self._lock:
            running = self._state["state"] == "running"
        if running:
            self._stop.set()
        return running

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def _set(self, **kw: Any) -> None:
        with self._lock:
            self._state.update(kw)

    def start(self, cfg: GenConfig, speed: str = "burst", time_scale: float = 60.0) -> str:
        """Validate and start a run. Raises ValueError for bad input and Busy if a run is active."""
        cfg.validate()
        if speed not in ("burst", "realtime"):
            raise ValueError("speed must be burst or realtime")
        if not 0 < time_scale <= 100000:
            raise ValueError("time_scale must be between 0 and 100000")
        run_id = uuid.uuid4().hex
        with self._lock:
            if self._state["state"] == "running":
                raise Busy("a run is already in progress")
            self._state.update(state="running", produced=0, run_id=run_id, total=0, error="", labels_path="")
            self._stop.clear()
        self._thread = threading.Thread(target=self._work, args=(cfg, speed, time_scale, run_id), daemon=True)
        self._thread.start()
        return run_id

    def wait(self, timeout: float = 60.0) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _work(self, cfg: GenConfig, speed: str, time_scale: float, run_id: str) -> None:
        try:
            events, labels = build_events(cfg)
            if self._stop.is_set():
                self._set(state="stopped")
                return
            labels["run_id"] = run_id
            path = write_labels(labels, self._labels_path())
            self._set(total=len(events), labels_path=path)
            if self._redis_factory is None:
                raise RuntimeError("no redis client configured")
            client = self._redis_factory()
            push_redis(events, client, speed, time_scale, progress=lambda n: self._set(produced=n),
                       sleep=self._sleep, should_stop=self._stop.is_set)
            if self._stop.is_set():
                log.info("run stopped", extra={"run_id": run_id, "events": self.status()["produced"]})
                self._set(state="stopped")
                return
            log.info("run finished", extra={"run_id": run_id, "events": len(events)})
            self._set(state="done")
        except Exception as exc:  # noqa: BLE001 - report to the caller through status
            log.error("run failed", extra={"run_id": run_id, "error": str(exc)[:300]})
            self._set(state="done", error=str(exc)[:300])
