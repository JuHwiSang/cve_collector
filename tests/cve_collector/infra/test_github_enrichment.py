from __future__ import annotations

import json
import tempfile

from cve_collector.core.domain.models import Vulnerability, Repository
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubRepoEnricher
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
            key = "gh_advisory:GHSA-42"
            # For repo enrichment we cache repo JSON under gh_repo:{owner}/{name}
            cache.set("gh_repo:owner/name", json.dumps({"stargazers_count": 7, "size": 100}).encode("utf-8"))
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(cache=cache, http_client=_StubHttp({}), app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7))
            v = Vulnerability(ghsa_id="GHSA-42", repositories=(Repository.from_github("owner", "name", ecosystem="pypi"),))
            out = enricher.enrich(v)
            assert out.repositories and out.repositories[0].star_count == 7
            assert out.repositories[0].size_bytes == 102400  # 100 KB * 1024
            assert out.repositories[0].ecosystem == "pypi"
