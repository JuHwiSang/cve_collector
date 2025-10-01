from __future__ import annotations

from typing import Protocol


class RateLimiterPort(Protocol):
    def acquire(self) -> None:
        """Block until a permit is available according to the configured rate."""


