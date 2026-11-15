"""Tiny in-memory fixed-window rate limiter for the expensive endpoints."""
import threading
import time
from typing import Callable

from .errors import ApiError


class RateLimiter:
    """Allow `limit` calls per `window_s` seconds per key."""

    def __init__(self, limit: int, window_s: float = 60.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit, self.window_s, self._clock = limit, window_s, clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if now - t < self.window_s]
            if len(recent) >= self.limit:
                self._hits[key] = recent
                raise ApiError("invalid_request", "rate limit exceeded; wait a moment and retry", status=429)
            recent.append(now)
            self._hits[key] = recent
