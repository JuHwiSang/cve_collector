from __future__ import annotations

import os
import tempfile

import pytest

from cve_collector.infra.cache_diskcache import DiskCacheAdapter


def test_diskcache_adapter_set_get_clear():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            cache.set("k", b"v")
            assert cache.get("k") == b"v"
            cache.clear()
            assert cache.get("k") is None


def test_diskcache_adapter_rejects_non_bytes():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            cache._cache.set("k", 123)
            with pytest.raises(TypeError):
                _ = cache.get("k")


