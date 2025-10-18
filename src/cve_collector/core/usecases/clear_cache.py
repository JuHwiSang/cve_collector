from __future__ import annotations

from ..ports.cache_port import CachePort


class ClearCacheUseCase:
    def __init__(self, cache: CachePort) -> None:
        self._cache = cache

    def execute(self, prefix: str | None = None) -> None:
        self._cache.clear(prefix=prefix)


