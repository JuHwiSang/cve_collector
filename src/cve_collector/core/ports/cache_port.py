from __future__ import annotations

from typing import Protocol


class CachePort(Protocol):
    def get(self, key: str) -> bytes | None:
        """Return cached bytes for key, or None if missing/expired."""

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None:
        """Store bytes with optional TTL in seconds."""

    def clear(self) -> None:
        """Clear all cached entries for the current namespace."""


