from __future__ import annotations

import json
import tempfile

from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.http_client import HttpClient
from cve_collector.infra.osv_index import OSVIndexAdapter


class _StubHttpJson(HttpClient):
	def __init__(self, payload: dict):
		super().__init__()
		self._payload = payload

	def get_json(self, url: str) -> dict:
		return self._payload


def test_osv_get_by_ghsa_populates_basic_fields():
	with tempfile.TemporaryDirectory() as tmp:
		with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
			payload = {
				"id": "GHSA-aaaa-bbbb-cccc",
				"aliases": ["CVE-2020-1234", "OTHER-1"],
				"summary": "Something bad",
			}
			adapter = OSVIndexAdapter(cache=cache, http_client=_StubHttpJson(payload))
			v = adapter.get_by_ghsa("GHSA-aaaa-bbbb-cccc")
			assert v is not None
			assert v.ghsa_id == "GHSA-aaaa-bbbb-cccc"
			assert v.cve_id == "CVE-2020-1234"
			assert v.summary == "Something bad"


def test_osv_get_by_ghsa_uses_cache_when_present():
	with tempfile.TemporaryDirectory() as tmp:
		with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
			key = "osv:ghsa:GHSA-xxxx-yyyy-zzzz"
			raw = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": [], "summary": "S"}
			cache.set(key, json.dumps(raw).encode("utf-8"))
			adapter = OSVIndexAdapter(cache=cache, http_client=_StubHttpJson({}))
			v = adapter.get_by_ghsa("GHSA-xxxx-yyyy-zzzz")
			assert v is not None
			assert v.summary == "S"
