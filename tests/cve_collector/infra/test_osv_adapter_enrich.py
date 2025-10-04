from __future__ import annotations

import json
import tempfile
import pytest

from cve_collector.core.domain.models import Vulnerability
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.http_client import HttpClient
from cve_collector.infra.osv_index import OSVAdapter


def test_osv_enrich_populates_fields_from_cache():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            key = "osv:ghsa:GHSA-aaaa-bbbb-cccc"
            payload = {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2020-1234"],
                "summary": "Summary from OSV",
                "details": "Details from OSV",
                "published": "2022-05-24T17:26:04Z",
                "modified": "2025-01-14T08:57:21.582603Z",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                "references": [
                    {"type": "FIX", "url": "https://github.com/owner/name/commit/abc1234567890"},
                    {"type": "PACKAGE", "url": "https://github.com/owner/name"},
                    {"type": "WEB", "url": "https://example.com/proof-of-concept"},
                ],
            }
            cache.set(key, json.dumps(payload).encode("utf-8"))

            adapter = OSVAdapter(cache=cache, http_client=HttpClient())
            v0 = Vulnerability(ghsa_id="GHSA-aaaa-bbbb-cccc")
            v = adapter.enrich(v0)

            assert v.cve_id == "CVE-2020-1234"
            assert v.summary == "Summary from OSV"
            assert v.description == "Details from OSV"
            assert v.severity is not None and v.severity.name == "UNKNOWN"
            assert v.published_at is not None and v.modified_at is not None
            # Repositories/commits/PoC
            assert any(r.slug == "owner/name" for r in v.repositories)
            assert any(c.short_hash == "abc123456789" for c in v.commits)
            assert any("proof-of-concept" in u for u in v.poc_urls)


class _StubHttp(HttpClient):
    def __init__(self, payload: dict):
        super().__init__()
        self._payload = payload

    def get_json(self, url: str) -> dict:
        return self._payload


def test_osv_get_by_ghsa_fetches_and_caches_when_missing():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            payload = {
                "id": "GHSA-zzzz-yyyy-xxxx",
                "aliases": ["CVE-2024-4242"],
                "summary": "S",
            }
            adapter = OSVAdapter(cache=cache, http_client=_StubHttp(payload))
            v = adapter.get_by_ghsa("GHSA-zzzz-yyyy-xxxx")
            assert v is not None
            assert v.ghsa_id == "GHSA-zzzz-yyyy-xxxx"
            assert v.cve_id == "CVE-2024-4242"


def test_osv_list_scans_cache_entries():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            for ghsa in ("GHSA-1", "GHSA-2"):
                raw = {"id": ghsa, "aliases": [], "summary": ghsa}
                cache.set(f"osv:ghsa:{ghsa}", json.dumps(raw).encode("utf-8"))
            adapter = OSVAdapter(cache=cache, http_client=HttpClient())
            lst = adapter.list(ecosystem="npm")
            ids = {v.ghsa_id for v in lst}
            assert {"GHSA-1", "GHSA-2"}.issubset(ids)


def test_osv_list_respects_limit():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            for ghsa in ("GHSA-1", "GHSA-2", "GHSA-3"):
                raw = {"id": ghsa, "aliases": [], "summary": ghsa}
                cache.set(f"osv:ghsa:{ghsa}", json.dumps(raw).encode("utf-8"))
            adapter = OSVAdapter(cache=cache, http_client=HttpClient())
            lst = adapter.list(ecosystem="npm", limit=2)
            assert len(lst) == 2


def test_osv_list_raises_on_invalid_json():
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            cache.set("osv:ghsa:BAD", b"not-json")
            adapter = OSVAdapter(cache=cache, http_client=HttpClient())
            with pytest.raises(json.JSONDecodeError):
                adapter.list(ecosystem="any")


