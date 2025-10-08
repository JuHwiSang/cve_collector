from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
import time


class ClockPort(Protocol):
    def now(self) -> datetime:
        """Return current UTC datetime."""
        ...

    def sleep(self, seconds: float) -> None:
        """Sleep for the given seconds."""


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


