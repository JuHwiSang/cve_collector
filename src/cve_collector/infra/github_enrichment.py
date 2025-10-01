from __future__ import annotations

from typing import Iterable

from ..core.domain.models import Commit, Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from ..shared.utils import is_poc_url, parse_github_commit_url, parse_github_repo_url
from ..core.domain.enums import Severity
from .http_client import HttpClient


ADVISORY_URL = "https://api.github.com/advisories/"


class GitHubAdvisoryEnricher(VulnerabilityEnrichmentPort):
    def __init__(self, cache: CachePort, http_client: HttpClient) -> None:
        self._cache = cache
        self._http = http_client

    def enrich(self, v: Vulnerability) -> Vulnerability:
        key = f"gh_advisory:{v.ghsa_id}"
        raw_bytes = self._cache.get(key)
        if raw_bytes is not None:
            import json as _json
            data = _json.loads(raw_bytes.decode("utf-8"))
        else:
            url = ADVISORY_URL + v.ghsa_id
            data = self._http.get_json(url)
            import json as _json
            self._cache.set(key, _json.dumps(data).encode("utf-8"))

        if not isinstance(data, dict):
            raise TypeError("GitHubAdvisoryEnricher invariant violated: expected JSON object")

        # Severity
        severity_value = data.get("severity")
        severity: Severity | None = None
        if isinstance(severity_value, str):
            try:
                severity = Severity[severity_value.upper()]
            except KeyError:
                severity = None

        # Identifiers → CVE
        cve_id: str | None = v.cve_id
        identifiers = data.get("identifiers")
        if isinstance(identifiers, list):
            for ident in identifiers:
                if isinstance(ident, dict) and ident.get("type") == "CVE":
                    val = ident.get("value")
                    if isinstance(val, str):
                        cve_id = val
                        break

        # References → repositories/commits/poc_urls
        repo_map: dict[str, Repository] = {}
        commits: list[Commit] = []
        poc_urls: list[str] = []
        references = data.get("references")
        if isinstance(references, list):
            for ref in references:
                url = ref.get("url") if isinstance(ref, dict) else None
                if not isinstance(url, str):
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

    def enrich_many(self, items: Iterable[Vulnerability]):
        for v in items:
            yield self.enrich(v)


