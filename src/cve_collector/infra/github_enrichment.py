from __future__ import annotations

import logging

from github import Github, GithubException, RateLimitExceededException

from ..core.domain.models import Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.dump_port import DumpProviderPort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort

logger = logging.getLogger(__name__)


# Negative cache markers for permanent failures
_ERROR_MARKER_PREFIX = "__error__"
_ERROR_TTL_SECONDS = 24 * 3600  # Cache errors for 1 day (shorter than normal cache)




class GitHubRepoEnricher(VulnerabilityEnrichmentPort, DumpProviderPort):
    def __init__(self, cache: CachePort, github_client: Github, github_cache_ttl_days: int, osv_cache_ttl_days: int) -> None:
        self._cache = cache
        self._github = github_client
        self._github_cache_ttl_days = github_cache_ttl_days
        self._osv_cache_ttl_days = osv_cache_ttl_days

    def enrich(self, v: Vulnerability) -> Vulnerability:
        """Augment GitHub-specific repository metadata only (e.g., star_count).

        This enricher does not derive severity, CVE, repositories, commits, or PoC links.
        It assumes repositories are already present (e.g., from OSV) and fills in
        GitHub repo fields that require calling the GitHub API (stars).
        """
        if not v.repositories:
            logger.debug("No repositories found for %s, skipping GitHub enrichment", v.ghsa_id)
            return v

        github_repos = [r for r in v.repositories if r.platform == "github" and r.owner and r.name]
        if github_repos:
            logger.info("Enriching %s with GitHub metadata for %d repositories", v.ghsa_id, len(github_repos))

        updated_repos: list[Repository] = []
        for repo in v.repositories:
            if repo.platform == "github" and repo.owner and repo.name:
                # Reuse dump() method to get repo data
                data = self.dump(f"{repo.owner}/{repo.name}")

                if data is None:
                    # dump() already handles errors and caching, just skip
                    updated_repos.append(repo)
                    continue

                stars: int | None = None
                size_bytes: int | None = None
                if isinstance(data, dict):
                    val = data.get("stargazers_count")
                    if isinstance(val, int):
                        stars = val
                    else:
                        stars = None

                    # GitHub API returns size in kilobytes, convert to bytes
                    size_val = data.get("size")
                    if isinstance(size_val, int):
                        size_bytes = size_val * 1024
                    else:
                        size_bytes = None

                    if stars is not None or size_bytes is not None:
                        logger.debug("Enriched %s/%s: stars=%s, size=%s bytes", repo.owner, repo.name, stars, size_bytes)

                # Preserve existing ecosystem from input repo
                updated_repos.append(Repository.from_github(repo.owner, repo.name, stars=stars, size_bytes=size_bytes, ecosystem=repo.ecosystem))
            else:
                updated_repos.append(repo)

        return v.with_updates(
            repositories=tuple(updated_repos)
        )

    # enrich_many provided by VulnerabilityEnrichmentPort default implementation

    def dump(self, id: str) -> dict | None:
        """Return raw GitHub repo JSON for owner/name format, or None if unsupported or missing."""
        # Expected format: "owner/name"
        if "/" not in id:
            return None

        parts = id.split("/", 1)
        if len(parts) != 2:
            return None

        owner, name = parts
        key = f"gh_repo:{owner}/{name}"
        data = self._cache.get_json(key)

        # Check for negative cache marker (previous errors)
        if isinstance(data, dict):
            if data.get(_ERROR_MARKER_PREFIX):
                logger.debug("Cache hit (error marker) for %s/%s", owner, name)
                return None
            logger.debug("Cache hit for %s/%s", owner, name)
            return data

        logger.debug("Fetching GitHub repo data for %s/%s", owner, name)
        try:
            repo = self._github.get_repo(f"{owner}/{name}")
            data = repo.raw_data

            ttl_seconds = int(self._github_cache_ttl_days) * 24 * 3600
            self._cache.set_json(key, data, ttl_seconds=ttl_seconds)
            logger.info("Successfully fetched and cached %s/%s", owner, name)
            return data

        except RateLimitExceededException:
            logger.error("GitHub API rate limit exceeded for repo %s/%s", owner, name)
            raise

        except GithubException as e:
            logger.warning("GitHub API error for repo %s/%s: %s", owner, name, e)
            error_marker = {_ERROR_MARKER_PREFIX: True}
            self._cache.set_json(key, error_marker, ttl_seconds=_ERROR_TTL_SECONDS)
            return None

        except Exception as e:
            logger.warning("Failed to fetch GitHub repo %s/%s: %s", owner, name, type(e).__name__)
            return None


