from __future__ import annotations

from ..core.domain.models import Commit, Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from ..shared.utils import is_poc_url, parse_github_commit_url, parse_github_repo_url
from ..core.ports.raw_port import RawProviderPort
from ..core.domain.enums import Severity
from .http_client import HttpClient
from .schemas import GitHubAdvisory, GhReference
from ..config.urls import get_github_advisory_url




class GitHubAdvisoryEnricher(VulnerabilityEnrichmentPort, RawProviderPort):
    def __init__(self, cache: CachePort, http_client: HttpClient) -> None:
        self._cache = cache
        self._http = http_client

    def enrich(self, v: Vulnerability) -> Vulnerability:
        """Enrich fields from GitHub advisory:

        - severity: map advisory severity string to Severity enum
        - cve_id: extract from identifiers where type == "CVE"
        - repositories/commits: parse GitHub repo/commit URLs from references
        - poc_urls: select references heuristically matching PoC keywords
        """
        key = f"gh_advisory:{v.ghsa_id}"
        data = self._cache.get_json(key)
        if data is None:
            url = get_github_advisory_url(v.ghsa_id)
            data = self._http.get_json(url)
            self._cache.set_json(key, data)

        advisory = GitHubAdvisory.model_validate(data)

        # Severity
        severity: Severity | None = None
        if advisory.severity is not None:
            try:
                severity = Severity[advisory.severity.upper()]
            except KeyError:
                severity = None

        # Identifiers → CVE
        cve_id: str | None = v.cve_id
        if advisory.identifiers:
            for ident in advisory.identifiers:
                if ident.type == "CVE":
                    cve_id = ident.value
                    break

        # References → repositories/commits/poc_urls
        repo_map: dict[str, Repository] = {}
        commits: list[Commit] = []
        poc_urls: list[str] = []
        references = advisory.references or []
        if references:
            for ref in references:
                url = ref.url if isinstance(ref, GhReference) else (ref if isinstance(ref, str) else "")
                if not url:
                    continue
                parsed_commit = parse_github_commit_url(url)
                if parsed_commit is not None:
                    owner, name, commit_hash = parsed_commit
                    repo = repo_map.get(f"{owner}/{name}")
                    if repo is None:
                        repo = Repository.from_github(owner, name)
                        repo_map[repo.slug or f"{owner}/{name}"] = repo
                    commits.append(Commit(repo=repo, hash=commit_hash))
                else:
                    parsed_repo = parse_github_repo_url(url)
                    if parsed_repo is not None:
                        owner, name = parsed_repo
                        repo = repo_map.get(f"{owner}/{name}")
                        if repo is None:
                            repo = Repository.from_github(owner, name)
                            repo_map[repo.slug or f"{owner}/{name}"] = repo
                    elif is_poc_url(url):
                        poc_urls.append(url)

        return v.with_updates(
            severity=severity if severity is not None else v.severity,
            cve_id=cve_id,
            repositories=tuple(repo_map.values()) if repo_map else v.repositories,
            commits=tuple(commits) if commits else v.commits,
            poc_urls=tuple(poc_urls) if poc_urls else v.poc_urls,
        )

    # enrich_many provided by VulnerabilityEnrichmentPort default implementation

    def get_raw(self, selector: str) -> dict | None:
        """Return raw GitHub advisory JSON for a GHSA selector, or None if unsupported or missing."""
        sel = selector.strip()
        if not sel.upper().startswith("GHSA-"):
            return None
        key = f"gh_advisory:{sel}"
        data = self._cache.get_json(key)
        if isinstance(data, dict):
            return data
        url = get_github_advisory_url(sel)
        try:
            data = self._http.get_json(url)
        except Exception:
            return None
        self._cache.set_json(key, data)
        return data


