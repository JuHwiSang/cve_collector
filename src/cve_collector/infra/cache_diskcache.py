from __future__ import annotations

import os
from typing import Optional

import diskcache as dc
from platformdirs import user_cache_dir

from ..core.ports.cache_port import CachePort


class DiskCacheAdapter(CachePort):
    def __init__(self, namespace: str, default_ttl_seconds: int = 0, base_dir: Optional[str] = None) -> None:
        self._namespace = namespace
        cache_dir = base_dir or os.getenv("CVE_COLLECTOR_CACHE_DIR")
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
            path = os.path.join(cache_dir, namespace)
        else:
            path = os.path.join(user_cache_dir("cve_collector"), namespace)
        os.makedirs(path, exist_ok=True)
        self._cache = dc.Cache(path)
        self._default_ttl = default_ttl_seconds

    def get(self, key: str) -> bytes | None:
        value = self._cache.get(key)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        raise TypeError("DiskCacheAdapter invariant violated: cached value is not bytes")

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        self._cache.set(key, value, expire=ttl if ttl > 0 else None)

    def clear(self) -> None:
        self._cache.clear()
        
    def close(self) -> None:
        self._cache.close()

    def __enter__(self) -> DiskCacheAdapter:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
