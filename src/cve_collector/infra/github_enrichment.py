from __future__ import annotations

from ..core.domain.models import Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from ..core.ports.raw_port import RawProviderPort
from .http_client import HttpClient
from ..config.urls import get_github_advisory_url, get_github_repo_url
from ..config.types import AppConfig




class GitHubRepoEnricher(VulnerabilityEnrichmentPort, RawProviderPort):
    def __init__(self, cache: CachePort, http_client: HttpClient, app_config: AppConfig) -> None:
        self._cache = cache
        self._http = http_client
        self._cfg = app_config

    def enrich(self, v: Vulnerability) -> Vulnerability:
        """Augment GitHub-specific repository metadata only (e.g., star_count).

        This enricher does not derive severity, CVE, repositories, commits, or PoC links.
        It assumes repositories are already present (e.g., from OSV) and fills in
        GitHub repo fields that require calling the GitHub API (stars).
        """
        if not v.repositories:
            return v

        updated_repos: list[Repository] = []
        for repo in v.repositories:
            if repo.platform == "github" and repo.owner and repo.name:
                key = f"gh_repo:{repo.owner}/{repo.name}"
                data = self._cache.get_json(key)
                if data is None:
                    url = get_github_repo_url(repo.owner, repo.name)
                    data = self._http.get_json(url)
                    # Cache with TTL from injected config (days → seconds)
                    ttl_seconds = int(self._cfg.github_cache_ttl_days) * 24 * 3600
                    self._cache.set_json(key, data, ttl_seconds=ttl_seconds)

                stars: int | None = None
                if isinstance(data, dict):
                    val = data.get("stargazers_count")
                    if isinstance(val, int):
                        stars = val
                    else:
                        stars = None
                updated_repos.append(Repository.from_github(repo.owner, repo.name, stars=stars))
            else:
                updated_repos.append(repo)

        return v.with_updates(
            repositories=tuple(updated_repos)
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
        ttl_seconds = int(self._cfg.github_cache_ttl_days) * 24 * 3600
        self._cache.set_json(key, data, ttl_seconds=ttl_seconds)
        return data


