from __future__ import annotations

import time

from cve_collector.infra.rate_limiter import SimpleRateLimiter, SlidingWindowRateLimiter


def test_simple_rate_limiter_enforces_interval():
    rl = SimpleRateLimiter(rps=10.0)  # 0.1s interval
    start = time.monotonic()
    rl.acquire()
    rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.09  # allow small timing variance


def test_sliding_window_allows_burst_within_limit():
    """Test that requests can burst up to the limit without blocking."""
    rl = SlidingWindowRateLimiter(max_requests=5, window_seconds=1.0)
    start = time.monotonic()

    # Should allow 5 requests immediately without blocking
    for _ in range(5):
        rl.acquire()

    elapsed = time.monotonic() - start
    assert elapsed < 0.1  # Should complete almost instantly


def test_sliding_window_blocks_when_limit_exceeded():
    """Test that the 6th request blocks until window slides."""
    rl = SlidingWindowRateLimiter(max_requests=5, window_seconds=1.0)

    # Make 5 requests immediately
    start = time.monotonic()
    for _ in range(5):
        rl.acquire()

    # 6th request should block for ~1 second
    rl.acquire()
    elapsed = time.monotonic() - start

    assert elapsed >= 0.95  # Should wait close to 1 second


def test_sliding_window_allows_requests_after_window_slides():
    """Test that old requests fall out of the window correctly."""
    rl = SlidingWindowRateLimiter(max_requests=3, window_seconds=0.5)

    # Make 3 requests
    for _ in range(3):
        rl.acquire()

    # Wait for window to partially slide
    time.sleep(0.6)

    # Should now allow 3 more requests without significant blocking
    start = time.monotonic()
    for _ in range(3):
        rl.acquire()
    elapsed = time.monotonic() - start

    assert elapsed < 0.1  # Should be fast since window has slid


def test_sliding_window_accurate_burst_handling():
    """Test that bursts are correctly limited over time."""
    rl = SlidingWindowRateLimiter(max_requests=10, window_seconds=1.0)

    start = time.monotonic()

    # Make 10 requests (should be instant)
    for _ in range(10):
        rl.acquire()

    first_batch = time.monotonic() - start
    assert first_batch < 0.1

    # Make 5 more requests (should block ~1 second total)
    for _ in range(5):
        rl.acquire()

    total_elapsed = time.monotonic() - start
    # First 10 instant, next 5 need to wait for window to slide
    assert total_elapsed >= 0.95
