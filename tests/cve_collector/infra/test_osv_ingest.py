from __future__ import annotations

import io
import json
import tempfile
import zipfile

from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.http_client import HttpClient
from cve_collector.infra.osv_adapter import OSVAdapter


def _make_zip_with_ghsa() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        payload = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2020-1234"],
            "summary": "Something bad",
        }
        zf.writestr("GHSA-aaaa-bbbb-cccc.json", json.dumps(payload))
    return buf.getvalue()


class _StubHttp(HttpClient):
    def __init__(self, content: bytes):
        super().__init__()
        self._content = content

    def get_bytes(self, url: str) -> bytes:
        return self._content

    def get_json(self, url: str) -> dict:
        # Not used in these tests
        return {}


def test_osv_ingest_zip_populates_cache_and_list():
    z = _make_zip_with_ghsa()
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            adapter = OSVAdapter(cache=cache, http_client=_StubHttp(z))
            count = adapter.ingest_zip("npm")
            assert count == 1
            v = adapter.get("GHSA-aaaa-bbbb-cccc")
            assert v is not None
            assert v.cve_id == "CVE-2020-1234"
            assert v.summary == "Something bad"
            lst = adapter.list(ecosystem="npm")
            assert len(lst) == 1
            assert lst[0].ghsa_id == "GHSA-aaaa-bbbb-cccc"


def test_osv_list_auto_ingests_when_empty():
    z = _make_zip_with_ghsa()
    with tempfile.TemporaryDirectory() as tmp:
        with DiskCacheAdapter(namespace="test", base_dir=tmp) as cache:
            adapter = OSVAdapter(cache=cache, http_client=_StubHttp(z))
            # No prior ingest; list should trigger ingest automatically
            lst = adapter.list(ecosystem="npm")
            assert len(lst) == 1
            assert lst[0].ghsa_id == "GHSA-aaaa-bbbb-cccc"


