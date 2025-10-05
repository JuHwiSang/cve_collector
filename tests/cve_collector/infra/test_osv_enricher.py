from __future__ import annotations

import json
import tempfile

from cve_collector.core.domain.models import Vulnerability
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.http_client import HttpClient
from cve_collector.infra.osv_adapter import OSVAdapter


class _StubHttp(HttpClient):
    def __init__(self, payload: dict):
        super().__init__()
        self._payload = payload

    def get_json(self, url: str) -> dict:
        return self._payload


def test_osv_enricher_enriches_basic_fields():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            payload = {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2020-1234"],
                "summary": "Sum",
                "details": "Desc",
                "published": "2024-01-01T00:00:00Z",
                "modified": "2024-02-01T00:00:00Z",
            }
            enricher = OSVAdapter(cache=cache, http_client=_StubHttp(payload))
            v = Vulnerability(ghsa_id="GHSA-aaaa-bbbb-cccc")
            out = enricher.enrich(v)
            assert out.cve_id == "CVE-2020-1234"
            assert out.summary == "Sum"
            assert out.description == "Desc"
            assert str(out.published_at).startswith("2024-01-01")
            assert str(out.modified_at).startswith("2024-02-01")


def test_osv_enricher_uses_cache_if_present():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            key = "osv:ghsa:GHSA-42"
            payload = {
                "id": "GHSA-42",
                "aliases": ["CVE-2024-0042"],
                "summary": "S",
            }
            cache.set(key, json.dumps(payload).encode("utf-8"))
            enricher = OSVAdapter(cache=cache, http_client=_StubHttp({}))
            v = Vulnerability(ghsa_id="GHSA-42")
            out = enricher.enrich(v)
            assert out.cve_id == "CVE-2024-0042"
            assert out.summary == "S"



