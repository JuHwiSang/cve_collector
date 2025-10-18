from __future__ import annotations

import logging
import httpx

from ..core.domain.models import Repository, Vulnerability
from ..core.ports.cache_port import CachePort
from ..core.ports.enrich_port import VulnerabilityEnrichmentPort
from ..core.ports.dump_port import DumpProviderPort
from .http_client import HttpClient
from ..config.urls import get_github_advisory_url, get_github_repo_url
from ..config.types import AppConfig

logger = logging.getLogger(__name__)


# Negative cache markers for permanent failures
_ERROR_MARKER_PREFIX = "__error__"
_ERROR_TTL_SECONDS = 24 * 3600  # Cache errors for 1 day (shorter than normal cache)




class GitHubRepoEnricher(VulnerabilityEnrichmentPort, DumpProviderPort):
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

                # Check for negative cache marker (previous errors)
                if isinstance(data, dict) and data.get(_ERROR_MARKER_PREFIX):
                    # Skip enrichment for repos that previously failed
                    logger.warning(
                        "Skipping GitHub repo enrichment due to cached error: %s/%s (status: %s)",
                        repo.owner, repo.name, data.get("status_code", "unknown")
                    )
                    updated_repos.append(repo)
                    continue

                if data is None:
                    url = get_github_repo_url(repo.owner, repo.name)
                    try:
                        data = self._http.get_json(url)
                        # Cache successful response with normal TTL
                        ttl_seconds = int(self._cfg.github_cache_ttl_days) * 24 * 3600
                        self._cache.set_json(key, data, ttl_seconds=ttl_seconds)
                    except httpx.HTTPStatusError as e:
                        # Cache 404 and other client errors to avoid repeated requests
                        if 400 <= e.response.status_code < 500:
                            logger.warning(
                                "GitHub API error for repo %s/%s: HTTP %d. Caching error marker.",
                                repo.owner, repo.name, e.response.status_code
                            )
                            error_marker = {
                                _ERROR_MARKER_PREFIX: True,
                                "status_code": e.response.status_code,
                                "url": str(e.request.url)
                            }
                            self._cache.set_json(key, error_marker, ttl_seconds=_ERROR_TTL_SECONDS)
                        else:
                            logger.warning(
                                "GitHub API server error for repo %s/%s: HTTP %d. Skipping without caching.",
                                repo.owner, repo.name, e.response.status_code
                            )
                        # Skip this repo and continue with others
                        updated_repos.append(repo)
                        continue
                    except Exception as e:
                        # For other errors (network, timeout), skip without caching
                        logger.warning(
                            "Failed to fetch GitHub repo %s/%s: %s. Skipping without caching.",
                            repo.owner, repo.name, type(e).__name__
                        )
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
                # Preserve existing ecosystem from input repo
                updated_repos.append(Repository.from_github(repo.owner, repo.name, stars=stars, size_bytes=size_bytes, ecosystem=repo.ecosystem))
            else:
                updated_repos.append(repo)

        return v.with_updates(
            repositories=tuple(updated_repos)
        )

    # enrich_many provided by VulnerabilityEnrichmentPort default implementation

    def dump(self, id: str) -> dict | None:
        """Return raw GitHub advisory JSON for a GHSA id, or None if unsupported or missing."""
        if not id.upper().startswith("GHSA-"):
            return None
        key = f"gh_advisory:{id}"
        data = self._cache.get_json(key)

        # Check for negative cache marker (previous errors)
        if isinstance(data, dict):
            if data.get(_ERROR_MARKER_PREFIX):
                logger.warning(
                    "Skipping GitHub advisory dump due to cached error: %s (status: %s)",
                    id, data.get("status_code", "unknown")
                )
                return None
            return data

        url = get_github_advisory_url(id)
        try:
            data = self._http.get_json(url)
            ttl_seconds = int(self._cfg.github_cache_ttl_days) * 24 * 3600
            self._cache.set_json(key, data, ttl_seconds=ttl_seconds)
            return data
        except httpx.HTTPStatusError as e:
            # Cache 404 and other client errors
            if 400 <= e.response.status_code < 500:
                logger.warning(
                    "GitHub API error for advisory %s: HTTP %d. Caching error marker.",
                    id, e.response.status_code
                )
                error_marker = {
                    _ERROR_MARKER_PREFIX: True,
                    "status_code": e.response.status_code,
                    "url": str(e.request.url)
                }
                self._cache.set_json(key, error_marker, ttl_seconds=_ERROR_TTL_SECONDS)
            else:
                logger.warning(
                    "GitHub API server error for advisory %s: HTTP %d. Skipping without caching.",
                    id, e.response.status_code
                )
            return None
        except Exception as e:
            logger.warning(
                "Failed to fetch GitHub advisory %s: %s. Skipping without caching.",
                id, type(e).__name__
            )
            return None


