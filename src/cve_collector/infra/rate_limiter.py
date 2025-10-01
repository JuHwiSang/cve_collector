from __future__ import annotations

import time
from threading import Lock

from ..core.ports.rate_limiter_port import RateLimiterPort


class SimpleRateLimiter(RateLimiterPort):
    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / max(0.0001, rps)
        self._lock = Lock()
        self._last: float = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


