from __future__ import annotations

import json
import tempfile

from cve_collector.core.domain.models import Vulnerability
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubRepoEnricher
from cve_collector.infra.http_client import HttpClient


class _StubHttp(HttpClient):
    def __init__(self, payload: dict):
        super().__init__()
        self._payload = payload

    def get_json(self, url: str) -> dict:
        return self._payload


def test_github_enricher_enriches_from_http_when_cache_empty():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            payload = {
                "severity": "HIGH",
                "references": [
                    {"url": "https://github.com/owner/name/commit/abc1234567890"},
                    {"url": "https://github.com/owner/name"},
                    {"url": "https://example.com/proof-of-concept"},
                ],
                "identifiers": [{"type": "CVE", "value": "CVE-2024-0001"}],
            }
            # AppConfig required, but tests may not use DI; pass a minimal stub
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(cache=cache, http_client=_StubHttp(payload), app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7))
            v = Vulnerability(ghsa_id="GHSA-1")
            out = enricher.enrich(v)
            assert out.cve_id == "CVE-2024-0001"
            assert out.severity is not None and out.severity.name == "HIGH"
            assert out.repositories and out.repositories[0].slug == "owner/name"
            assert out.commits and out.commits[0].short_hash == "abc123456789"
            assert any("proof-of-concept" in u for u in out.poc_urls)


def test_github_enricher_uses_cache_if_present():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            key = "gh_advisory:GHSA-42"
            cached = {
                "severity": "LOW",
                "references": [],
                "identifiers": [{"type": "CVE", "value": "CVE-2024-0042"}],
            }
            cache.set(key, json.dumps(cached).encode("utf-8"))
            from cve_collector.config.types import AppConfig
            enricher = GitHubRepoEnricher(cache=cache, http_client=_StubHttp({}), app_config=AppConfig(github_token=None, cache_dir=None, github_cache_ttl_days=30, osv_cache_ttl_days=7))
            v = Vulnerability(ghsa_id="GHSA-42")
            out = enricher.enrich(v)
            assert out.cve_id == "CVE-2024-0042"
            assert out.severity is not None and out.severity.name == "LOW"
