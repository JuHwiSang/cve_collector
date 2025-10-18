from __future__ import annotations

import tempfile
import pytest

from cve_collector.core.usecases.clear_cache import ClearCacheUseCase
from cve_collector.infra.cache_diskcache import DiskCacheAdapter


def test_clear_cache_usecase_clears_all():
    """Test that use case clears all cache when prefix is None."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state

            # Set up test data
            cache.set("osv:123", b"value1")
            cache.set("gh_repo:owner/name", b"value2")

            # Execute use case without prefix
            uc = ClearCacheUseCase(cache=cache)
            uc.execute()

            # Verify all keys are gone
            assert cache.get("osv:123") is None
            assert cache.get("gh_repo:owner/name") is None


def test_clear_cache_usecase_clears_prefix():
    """Test that use case clears only matching prefix when specified."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state

            # Set up test data
            cache.set("osv:123", b"value1")
            cache.set("osv:456", b"value2")
            cache.set("gh_repo:owner/name", b"value3")

            # Execute use case with prefix
            uc = ClearCacheUseCase(cache=cache)
            uc.execute(prefix="osv:")

            # Verify osv: keys are gone, gh_repo: remains
            assert cache.get("osv:123") is None
            assert cache.get("osv:456") is None
            assert cache.get("gh_repo:owner/name") == b"value3"
