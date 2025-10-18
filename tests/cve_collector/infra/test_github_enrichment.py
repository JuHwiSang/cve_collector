from __future__ import annotations

import json
import tempfile
import httpx

from cve_collector.core.domain.models import Vulnerability, Repository
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubRepoEnricher, _ERROR_MARKER_PREFIX
from cve_collector.infra.http_client import HttpClient


class _StubHttp(HttpClient):
    def __init__(self, payload: dict):
        super().__init__()
        self._payload = payload

    def get_json(self, url: str) -> dict:
        return self._payload


def test_github_repo_enricher_sets_stars_from_http_when_cache_empty():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            payload = {"stargazers_count": 12345, "size": 500}  # size in KB
            # AppConfig required, but tests may not use DI; pass a minimal stub
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(cache=cache, http_client=_StubHttp(payload), app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7))
            v = Vulnerability(ghsa_id="GHSA-1", repositories=(Repository.from_github("owner", "name", ecosystem="npm"),))
            out = enricher.enrich(v)
            assert out.repositories and out.repositories[0].slug == "owner/name"
            assert out.repositories[0].star_count == 12345
            assert out.repositories[0].size_bytes == 512000  # 500 KB * 1024
            assert out.repositories[0].ecosystem == "npm"


def test_github_repo_enricher_uses_cache_if_present():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            # For repo enrichment we cache repo JSON under gh_repo:{owner}/{name}
            cache.set("gh_repo:owner/name", json.dumps({"stargazers_count": 7, "size": 100}).encode("utf-8"))
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(cache=cache, http_client=_StubHttp({}), app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7))
            v = Vulnerability(ghsa_id="GHSA-42", repositories=(Repository.from_github("owner", "name", ecosystem="pypi"),))
            out = enricher.enrich(v)
            assert out.repositories and out.repositories[0].star_count == 7
            assert out.repositories[0].size_bytes == 102400  # 100 KB * 1024
            assert out.repositories[0].ecosystem == "pypi"


class _StubHttp404(HttpClient):
    """Stub HTTP client that raises 404 for all requests."""
    def __init__(self):
        super().__init__()

    def get_json(self, url: str) -> dict:
        # Simulate a 404 response
        request = httpx.Request("GET", url)
        response = httpx.Response(404, request=request, json={"message": "Not Found"})
        raise httpx.HTTPStatusError("404 Not Found", request=request, response=response)


def test_github_repo_enricher_handles_404_and_caches_error():
    """Test that 404 errors are handled gracefully and cached as error markers."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(
                cache=cache,
                http_client=_StubHttp404(),
                app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7)
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
            assert cached_data.get("status_code") == 404


def test_github_repo_enricher_skips_cached_errors():
    """Test that cached error markers prevent repeated API calls."""
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            from cve_collector.config.types import AppConfig

            # Pre-populate cache with error marker
            error_marker = {
                _ERROR_MARKER_PREFIX: True,
                "status_code": 404,
                "url": "https://api.github.com/repos/deleted/repo"
            }
            cache.set_json("gh_repo:deleted/repo", error_marker)

            # Use a regular stub that would succeed - should not be called
            enricher = GitHubRepoEnricher(
                cache=cache,
                http_client=_StubHttp({"stargazers_count": 999, "size": 100}),
                app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7)
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
