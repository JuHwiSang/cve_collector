from __future__ import annotations

from typing import Iterable, Sequence
import json
import io
import zipfile
from datetime import datetime

from ..core.domain.models import Vulnerability, Repository, Commit
from ..core.domain.enums import Severity
from ..core.ports.cache_port import CachePort
from ..core.ports.list_port import VulnerabilityListPort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from .http_client import HttpClient
from .schemas import OsvVulnerability
from ..config.urls import get_osv_zip_url, get_osv_vuln_url
from ..shared.utils import parse_github_commit_url, parse_github_repo_url, is_poc_url




def _to_domain(osv: OsvVulnerability) -> Vulnerability:
    cve_id: str | None = None
    for a in (osv.aliases or []):
        if a.startswith("CVE-"):
            cve_id = a
            break
    return Vulnerability(ghsa_id=osv.id, cve_id=cve_id, summary=osv.summary)


class OSVAdapter(VulnerabilityListPort, VulnerabilityEnrichmentPort):
    def __init__(self, cache: CachePort, http_client: HttpClient) -> None:
        self._cache = cache
        self._http = http_client

    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        result: list[Vulnerability] = []
        keys = list(self._cache.iter_keys("osv:ghsa:"))
        if not keys:
            # No cached entries yet; ingest for the requested ecosystem
            self.ingest_zip(ecosystem)
            keys = list(self._cache.iter_keys("osv:ghsa:"))
        for key in keys:
            osv = self._cache.get_model(key, OsvVulnerability)  # raises if invalid JSON
            if osv is None:
                continue
            result.append(_to_domain(osv))
            if limit is not None and len(result) >= limit:
                break
        return result

    def get(self, selector: str) -> Vulnerability | None:
        sel = selector.strip()
        if sel.upper().startswith("GHSA-"):
            return self.get_by_ghsa(sel)
        if sel.upper().startswith("CVE-"):
            # OSV is GHSA-centric in our adapter; try to resolve by scanning cache
            # for an entry whose aliases include the CVE, otherwise fetch by GHSA
            # is not possible without a mapping. We attempt a best-effort scan.
            for key in self._cache.iter_keys("osv:ghsa:"):
                osv = self._cache.get_model(key, OsvVulnerability)
                if osv and any(a == sel for a in (osv.aliases or [])):
                    return _to_domain(osv)
            # Fallback: no mapping found
            return None
        raise ValueError(f"Unsupported selector: {selector}")

    def get_by_ghsa(self, ghsa_id: str) -> Vulnerability | None:
        key = f"osv:ghsa:{ghsa_id}"
        osv = self._cache.get_model(key, OsvVulnerability)
        if osv is None:
            url = get_osv_vuln_url(ghsa_id)
            raw = self._http.get_json(url)  # raise on HTTP/JSON invariants
            osv = OsvVulnerability.model_validate(raw)
            self._cache.set_model(key, osv)
        return _to_domain(osv)

    def ingest_zip(self, ecosystem: str) -> int:
        zip_url = get_osv_zip_url(ecosystem)
        content = self._http.get_bytes(zip_url)
        buf = io.BytesIO(content)
        count = 0
        with zipfile.ZipFile(buf) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if not (name.startswith("GHSA-") and name.endswith(".json")):
                    continue
                raw_bytes = zf.read(info)
                raw_text = raw_bytes.decode("utf-8")
                data = json.loads(raw_text)
                osv = OsvVulnerability.model_validate(data)
                ghsa_id = osv.id
                self._cache.set_model(f"osv:ghsa:{ghsa_id}", osv)
                count += 1
        return count

    def enrich(self, v: Vulnerability) -> Vulnerability:
        """Enrich fields from OSV:

        - cve_id: from aliases
        - severity: UNKNOWN if OSV carries any severity entries
        - summary/description: fallback from OSV
        - published_at/modified_at: parsed from ISO timestamps
        - repositories/commits: parsed from references (GitHub repo/commit URLs)
        - poc_urls: references heuristically matching PoC keywords
        """
        key = f"osv:ghsa:{v.ghsa_id}"
        osv = self._cache.get_model(key, OsvVulnerability)
        if osv is None:
            url = get_osv_vuln_url(v.ghsa_id)
            raw = self._http.get_json(url)
            osv = OsvVulnerability.model_validate(raw)
            self._cache.set_model(key, osv)
        
        # CVE
        cve_id = v.cve_id
        for a in (osv.aliases or []):
            if a.startswith("CVE-"):
                cve_id = a
                break

        # Severity (best-effort from presence)
        severity: Severity | None = v.severity
        if osv.severity:
            severity = severity or Severity.UNKNOWN

        # Summary/Description
        summary = v.summary or osv.summary
        description = v.description or osv.details

        # Timestamps
        published_at = v.published_at
        modified_at = v.modified_at
        if osv.published:
            try:
                published_at = datetime.fromisoformat(osv.published.replace("Z", "+00:00"))
            except Exception:
                published_at = v.published_at
        if osv.modified:
            try:
                modified_at = datetime.fromisoformat(osv.modified.replace("Z", "+00:00"))
            except Exception:
                modified_at = v.modified_at

        # References → repositories/commits/poc_urls
        repo_map: dict[str, Repository] = {r.slug: r for r in v.repositories if r.slug} if v.repositories else {}
        commits: list[Commit] = list(v.commits) if v.commits else []
        poc_urls: list[str] = list(v.poc_urls) if v.poc_urls else []
        if osv.references:
            for ref in osv.references:
                rtype = (ref.type or "").upper()
                url = ref.url
                # Prefer commit extraction for FIX/WEB/OTHER (exclude ADVISORY/PACKAGE)
                if rtype in ("FIX", "WEB", "OTHER") and rtype not in ("ADVISORY", "PACKAGE"):
                    parsed_commit = parse_github_commit_url(url)
                    if parsed_commit is not None:
                        owner, name, commit_hash = parsed_commit
                        key_slug = f"{owner}/{name}"
                        repo = repo_map.get(key_slug)
                        if repo is None:
                            repo = Repository.from_github(owner, name)
                            repo_map[key_slug] = repo
                        commits.append(Commit(repo=repo, hash=commit_hash))
                        continue
                # Prefer repository extraction for PACKAGE/WEB
                if rtype in ("PACKAGE", "WEB"):
                    parsed_repo = parse_github_repo_url(url)
                    if parsed_repo is not None:
                        owner, name = parsed_repo
                        key_slug = f"{owner}/{name}"
                        if key_slug not in repo_map:
                            repo_map[key_slug] = Repository.from_github(owner, name)
                        continue
                # PoC URLs are typically WEB/OTHER; ignore ADVISORY/PACKAGE for PoC
                if rtype in ("WEB", "OTHER") and is_poc_url(url):
                    poc_urls.append(url)

        return v.with_updates(
            cve_id=cve_id,
            severity=severity,
            summary=summary,
            description=description,
            published_at=published_at,
            modified_at=modified_at,
            repositories=tuple(repo_map.values()) if repo_map else v.repositories,
            commits=tuple(commits) if commits else v.commits,
            poc_urls=tuple(poc_urls) if poc_urls else v.poc_urls,
        )

    # enrich_many provided by VulnerabilityEnrichmentPort default implementation


