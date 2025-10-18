from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Optional

from ..core.ports.rate_limiter_port import RateLimiterPort
from ..core.ports.cache_port import CachePort


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

    Supports optional persistent storage via CachePort for cross-process rate limiting.

    Example:
        # GitHub API: 5000 requests/hour for authenticated users
        limiter = SlidingWindowRateLimiter(max_requests=5000, window_seconds=3600.0)

        # With persistence and namespace (for token-specific limits)
        limiter = SlidingWindowRateLimiter(
            max_requests=5000,
            window_seconds=3600.0,
            cache=cache_port,
            namespace="gh_token_abc123"
        )

        # Or for testing: 60 requests/minute
        limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60.0)
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        cache: CachePort | None = None,
        namespace: str | None = None,
    ) -> None:
        """Initialize sliding window rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds (e.g., 3600.0 for 1 hour)
            cache: Optional CachePort for persistent storage across processes
            namespace: Optional namespace for cache keys (e.g., hashed token).
                      Cache is only used if namespace is provided. If namespace is None,
                      operates in memory-only mode regardless of cache parameter.
        """
        self._max_requests = max_requests
        self._window = window_seconds
        self._cache = cache if namespace else None  # Only use cache if namespace is provided
        self._namespace = namespace
        self._timestamps: deque[float] = deque()
        self._lock = Lock()

        # Load timestamps from cache if available
        if self._cache and self._namespace:
            self._load_from_cache()

    def _get_cache_prefix(self) -> str:
        """Get cache key prefix for this rate limiter."""
        return f"rate_limit:{self._namespace}:"

    def _load_from_cache(self) -> None:
        """Load timestamps from cache into memory deque."""
        if not self._cache or not self._namespace:
            return

        prefix = self._get_cache_prefix()
        now = time.time()
        cutoff = now - self._window

        # Load all timestamps from cache
        timestamps: list[float] = []
        for key in self._cache.iter_keys(prefix):
            # Extract timestamp from key: "rate_limit:{namespace}:{timestamp}"
            try:
                ts_str = key.split(":")[-1]
                ts = float(ts_str)
                if ts > cutoff:  # Only keep recent timestamps
                    timestamps.append(ts)
            except (ValueError, IndexError):
                continue

        # Sort and populate deque
        timestamps.sort()
        self._timestamps = deque(timestamps)

    def _save_timestamp_to_cache(self, timestamp: float) -> None:
        """Save a single timestamp to cache."""
        if not self._cache or not self._namespace:
            return

        key = f"{self._get_cache_prefix()}{timestamp}"
        # Set TTL slightly longer than window to handle clock skew
        ttl = int(self._window + 60)
        self._cache.set(key, b"", ttl_seconds=ttl)

    def _cleanup_old_cache_entries(self, cutoff: float) -> None:
        """Remove cache entries older than cutoff timestamp."""
        if not self._cache or not self._namespace:
            return

        prefix = self._get_cache_prefix()
        for key in self._cache.iter_keys(prefix):
            try:
                ts_str = key.split(":")[-1]
                ts = float(ts_str)
                if ts <= cutoff:
                    # Delete by clearing with exact key prefix
                    self._cache.clear(prefix=key)
            except (ValueError, IndexError):
                continue

    def acquire(self) -> None:
        """Acquire permission to make a request, blocking if necessary.

        This method will sleep if the rate limit would be exceeded,
        waiting until the oldest request falls outside the time window.
        """
        with self._lock:
            # Reload from cache to sync with other processes
            if self._cache and self._namespace:
                self._load_from_cache()

            now = time.time()  # Use time.time() for cache compatibility
            cutoff = now - self._window

            # Remove timestamps outside the current window
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()

            # Cleanup old cache entries periodically
            if self._cache and self._namespace:
                self._cleanup_old_cache_entries(cutoff)

            # If at capacity, wait until oldest request exits the window
            if len(self._timestamps) >= self._max_requests:
                sleep_until = self._timestamps[0] + self._window
                wait = sleep_until - now
                if wait > 0:
                    time.sleep(wait)

                # Reload and clean up again after sleeping
                if self._cache and self._namespace:
                    self._load_from_cache()
                now = time.time()
                cutoff = now - self._window
                while self._timestamps and self._timestamps[0] <= cutoff:
                    self._timestamps.popleft()

            # Record current request timestamp
            now = time.time()
            self._timestamps.append(now)

            # Save to cache if enabled
            if self._cache and self._namespace:
                self._save_timestamp_to_cache(now)


