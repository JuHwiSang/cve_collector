from __future__ import annotations

from typing import Sequence

from ..core.domain.models import Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.index_port import VulnerabilityIndexPort
from .http_client import HttpClient


OSV_API_BASE = "https://api.osv.dev/v1/vulns/"


class OSVIndexAdapter(VulnerabilityIndexPort):
    def __init__(self, cache: CachePort, http_client: HttpClient) -> None:
        self._cache = cache
        self._http = http_client

    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        # Not implemented yet: listing by ecosystem
        return []

    def get_by_ghsa(self, ghsa_id: str) -> Vulnerability | None:
        key = f"osv:ghsa:{ghsa_id}"
        cached = self._cache.get(key)
        if cached is not None:
            import json as _json
            try:
                raw = _json.loads(cached.decode("utf-8"))
            except Exception as exc:
                raise TypeError("Invalid cached value for OSV GHSA") from exc
        else:
            url = f"{OSV_API_BASE}{ghsa_id}"
            try:
                raw = self._http.get_json(url)
            except Exception:
                return None
            import json as _json
            self._cache.set(key, _json.dumps(raw).encode("utf-8"))

        ghsa = str(raw.get("id") or ghsa_id)
        aliases = raw.get("aliases") or []
        cve_id: str | None = None
        for a in aliases:
            if isinstance(a, str) and a.startswith("CVE-"):
                cve_id = a
                break
        summary = raw.get("summary") if isinstance(raw.get("summary"), str) else None
        return Vulnerability(ghsa_id=ghsa, cve_id=cve_id, summary=summary)


