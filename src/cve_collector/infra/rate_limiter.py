from __future__ import annotations

import time
from collections import deque
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


class SlidingWindowRateLimiter(RateLimiterPort):
    """Sliding window rate limiter that tracks requests over a time window.

    This is more sophisticated than SimpleRateLimiter and handles time-based limits
    like "5000 requests per hour" more accurately by tracking actual request timestamps.

    Example:
        # GitHub API: 5000 requests/hour for authenticated users
        limiter = SlidingWindowRateLimiter(max_requests=5000, window_seconds=3600.0)

        # Or for testing: 60 requests/minute
        limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60.0)
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        """Initialize sliding window rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds (e.g., 3600.0 for 1 hour)
        """
        self._max_requests = max_requests
        self._window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = Lock()

    def acquire(self) -> None:
        """Acquire permission to make a request, blocking if necessary.

        This method will sleep if the rate limit would be exceeded,
        waiting until the oldest request falls outside the time window.
        """
        with self._lock:
            now = time.monotonic()

            # Remove timestamps outside the current window
            while self._timestamps and self._timestamps[0] <= now - self._window:
                self._timestamps.popleft()

            # If at capacity, wait until oldest request exits the window
            if len(self._timestamps) >= self._max_requests:
                sleep_until = self._timestamps[0] + self._window
                wait = sleep_until - now
                if wait > 0:
                    time.sleep(wait)

                # Clean up again after sleeping
                now = time.monotonic()
                while self._timestamps and self._timestamps[0] <= now - self._window:
                    self._timestamps.popleft()

            # Record current request timestamp
            self._timestamps.append(time.monotonic())


