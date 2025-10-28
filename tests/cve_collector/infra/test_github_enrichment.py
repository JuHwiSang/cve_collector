from __future__ import annotations

import json
import tempfile
from unittest.mock import Mock

import pytest
from github import GithubException, RateLimitExceededException, UnknownObjectException

from cve_collector.core.domain.models import Vulnerability, Repository
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubRepoEnricher, _ERROR_MARKER_PREFIX


def _create_mock_github_client(raw_data: dict | None = None, exception: Exception | None = None):
    """Create a mock Github client that returns raw_data or raises exception."""
    mock_client = Mock()
    mock_repo = Mock()

    if exception:
        mock_client.get_repo.side_effect = exception
    elif raw_data:
        mock_repo.raw_data = raw_data
        mock_client.get_repo.return_value = mock_repo
    else:
        mock_client.get_repo.return_value = mock_repo

    return mock_client


def test_github_repo_enricher_sets_stars_from_http_when_cache_empty():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            raw_data = {"stargazers_count": 12345, "size": 500}  # size in KB
            mock_client = _create_mock_github_client(raw_data=raw_data)
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(ghsa_id="GHSA-1", repositories=(Repository.from_github("owner", "name", ecosystem="npm"),))
            out = enricher.enrich(v)
            assert out.repositories and out.repositories[0].slug == "owner/name"
            assert out.repositories[0].star_count == 12345
            assert out.repositories[0].size_bytes == 512000  # 500 KB * 1024
            assert out.repositories[0].ecosystem == "npm"
            mock_client.get_repo.assert_called_once_with("owner/name")


def test_github_repo_enricher_uses_cache_if_present():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            # For repo enrichment we cache repo JSON under gh_repo:{owner}/{name}
            cache.set("gh_repo:owner/name", json.dumps({"stargazers_count": 7, "size": 100}).encode("utf-8"))
            mock_client = _create_mock_github_client()  # Should not be called
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(ghsa_id="GHSA-42", repositories=(Repository.from_github("owner", "name", ecosystem="pypi"),))
            out = enricher.enrich(v)
            assert out.repositories and out.repositories[0].star_count == 7
            assert out.repositories[0].size_bytes == 102400  # 100 KB * 1024
            assert out.repositories[0].ecosystem == "pypi"
            mock_client.get_repo.assert_not_called()  # Cache hit, no API call


def test_github_repo_enricher_handles_404_and_caches_error():
    """Test that 404 errors (GithubException) are handled gracefully and cached as error markers."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            # PyGithub raises GithubException for 404
            mock_client = _create_mock_github_client(
                exception=GithubException(404, {"message": "Not Found"}, None)
            )
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(
                ghsa_id="GHSA-404",
                repositories=(Repository.from_github("deleted", "repo", ecosystem="npm"),)
            )

            # First call: should handle 404 and cache error marker
            out = enricher.enrich(v)

            # Repository should still be in output (not enriched)
            assert out.repositories and len(out.repositories) == 1
            assert out.repositories[0].owner == "deleted"
            assert out.repositories[0].name == "repo"
            assert out.repositories[0].star_count is None  # Not enriched

            # Check that error marker was cached
            cached_data = cache.get_json("gh_repo:deleted/repo")
            assert cached_data is not None
            assert isinstance(cached_data, dict)
            assert cached_data.get(_ERROR_MARKER_PREFIX) is True


def test_github_repo_enricher_skips_cached_errors():
    """Test that cached error markers prevent repeated API calls."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state

            # Pre-populate cache with error marker
            error_marker = {_ERROR_MARKER_PREFIX: True}
            cache.set_json("gh_repo:deleted/repo", error_marker)

            # Use a mock client that would succeed - should not be called
            mock_client = _create_mock_github_client(raw_data={"stargazers_count": 999, "size": 100})
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(
                ghsa_id="GHSA-404",
                repositories=(Repository.from_github("deleted", "repo", ecosystem="npm"),)
            )

            # Should skip enrichment due to cached error
            out = enricher.enrich(v)

            # Should not be enriched (star_count should be None, not 999)
            assert out.repositories and len(out.repositories) == 1
            assert out.repositories[0].star_count is None
            mock_client.get_repo.assert_not_called()  # Cache hit (error marker), no API call


def test_github_repo_enricher_raises_on_rate_limit():
    """Test that rate limit errors (RateLimitExceededException) are propagated (not cached)."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            # PyGithub raises RateLimitExceededException for rate limit
            mock_client = _create_mock_github_client(
                exception=RateLimitExceededException(
                    403,
                    {"message": "API rate limit exceeded"},
                    None
                )
            )
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(
                ghsa_id="GHSA-RATE",
                repositories=(Repository.from_github("popular", "repo", ecosystem="npm"),)
            )

            # Should raise RateLimitExceededException
            with pytest.raises(RateLimitExceededException):
                enricher.enrich(v)

            # Verify error was NOT cached (rate limit should not be cached)
            cached_data = cache.get_json("gh_repo:popular/repo")
            assert cached_data is None


def test_github_repo_enricher_caches_403_access_denied():
    """Test that non-rate-limit 403 errors (GithubException) are cached as error markers."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.clear()  # Ensure clean state
            # PyGithub raises GithubException for 403 access denied
            mock_client = _create_mock_github_client(
                exception=GithubException(403, {"message": "Repository access blocked"}, None)
            )
            enricher = GitHubRepoEnricher(
                cache=cache,
                github_client=mock_client,
                github_cache_ttl_days=30,
                osv_cache_ttl_days=7,
            )
            v = Vulnerability(
                ghsa_id="GHSA-403",
                repositories=(Repository.from_github("private", "repo", ecosystem="npm"),)
            )

            # Should handle 403 access denied and cache error marker
            out = enricher.enrich(v)

            # Repository should still be in output (not enriched)
            assert out.repositories and len(out.repositories) == 1
            assert out.repositories[0].star_count is None

            # Check that error marker was cached
            cached_data = cache.get_json("gh_repo:private/repo")
            assert cached_data is not None
            assert isinstance(cached_data, dict)
            assert cached_data.get(_ERROR_MARKER_PREFIX) is True
