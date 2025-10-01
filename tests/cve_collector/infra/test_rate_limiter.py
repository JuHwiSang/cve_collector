from __future__ import annotations

import time

from cve_collector.infra.rate_limiter import SimpleRateLimiter


def test_simple_rate_limiter_enforces_interval():
    rl = SimpleRateLimiter(rps=10.0)  # 0.1s interval
    start = time.monotonic()
    rl.acquire()
    rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.09  # allow small timing variance
