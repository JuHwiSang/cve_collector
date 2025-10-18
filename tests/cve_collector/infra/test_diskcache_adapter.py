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


def test_diskcache_adapter_clear_with_prefix():
    """Test that clear with prefix removes only keys matching the given prefix."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state

            # Set up test data with different prefixes
            cache.set("osv:123", b"value1")
            cache.set("osv:456", b"value2")
            cache.set("gh_repo:owner/name", b"value3")
            cache.set("other:key", b"value4")

            # Verify all keys exist
            assert cache.get("osv:123") == b"value1"
            assert cache.get("osv:456") == b"value2"
            assert cache.get("gh_repo:owner/name") == b"value3"
            assert cache.get("other:key") == b"value4"

            # Clear only osv: prefix
            cache.clear(prefix="osv:")

            # Verify osv: keys are gone, others remain
            assert cache.get("osv:123") is None
            assert cache.get("osv:456") is None
            assert cache.get("gh_repo:owner/name") == b"value3"
            assert cache.get("other:key") == b"value4"

            # Clear gh_repo: prefix
            cache.clear(prefix="gh_repo:")

            # Verify gh_repo: key is gone, other: remains
            assert cache.get("gh_repo:owner/name") is None
            assert cache.get("other:key") == b"value4"


def test_diskcache_adapter_clear_prefix_empty():
    """Test that clear with non-matching prefix doesn't affect anything."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state

            cache.set("osv:123", b"value1")
            cache.set("gh_repo:owner/name", b"value2")

            # Clear non-existent prefix
            cache.clear(prefix="nonexistent:")

            # Verify all keys still exist
            assert cache.get("osv:123") == b"value1"
            assert cache.get("gh_repo:owner/name") == b"value2"


