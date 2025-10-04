from __future__ import annotations

import json

from ..core.domain.models import Commit, Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from ..shared.utils import is_poc_url, parse_github_commit_url, parse_github_repo_url
from ..core.domain.enums import Severity
from .http_client import HttpClient
from .schemas import GitHubAdvisory, GhReference
from ..config.urls import get_github_advisory_url




class GitHubAdvisoryEnricher(VulnerabilityEnrichmentPort):
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
        raw_bytes = self._cache.get(key)
        if raw_bytes is not None:
            raw = json.loads(raw_bytes.decode("utf-8"))
        else:
            url = get_github_advisory_url(v.ghsa_id)
            raw = self._http.get_json(url)
            self._cache.set(key, json.dumps(raw).encode("utf-8"))

        data = GitHubAdvisory.model_validate(raw)

        # Severity
        severity: Severity | None = None
        if data.severity is not None:
            try:
                severity = Severity[data.severity.upper()]
            except KeyError:
                severity = None

        # Identifiers → CVE
        cve_id: str | None = v.cve_id
        if data.identifiers:
            for ident in data.identifiers:
                if ident.type == "CVE":
                    cve_id = ident.value
                    break

        # References → repositories/commits/poc_urls
        repo_map: dict[str, Repository] = {}
        commits: list[Commit] = []
        poc_urls: list[str] = []
        references = data.references or []
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


