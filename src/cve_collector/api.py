from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Sequence

from .app.container import Container
from .config.settings import AppConfig
from .core.domain.models import Vulnerability


@contextmanager
def _provide_container(config_override: AppConfig | None = None) -> Iterator[Container]:
    """Create and initialize a DI container.

    Args:
        config_override: Optional AppConfig to override default configuration.
                        If None, configuration is loaded from environment variables
                        and .env file using Pydantic BaseSettings.
    """
    container = Container()
    if config_override:
        container.config.from_pydantic(config_override)
    container.init_resources()
    try:
        yield container
    finally:
        container.shutdown_resources()


def list_vulnerabilities(
    *,
    ecosystem: str | None = None,
    limit: int | None = None,
    detailed: bool = False,
    filter_expr: str | None = None,
    config: AppConfig | None = None,
    github_token: str | None = None,
) -> Sequence[Vulnerability]:
    """Return a list of vulnerabilities. When detailed=True, items are enriched via configured enrichers.

    Args:
        ecosystem: Ecosystem name (e.g., npm). If None, lists all ecosystems.
        limit: Maximum number of results to return. If None, returns all results.
        detailed: If True, enriches items with additional metadata (GitHub stars, size, etc.).
        filter_expr: Filter expression using Python syntax. Examples: 'stars > 1000', 'severity == "HIGH"', 'has_cve and stars > 500'.
                    Filter variables: ghsa_id, cve_id, has_cve, severity, summary, description, details,
                    published_at, modified_at, ecosystem, repo_slug, stars, size_bytes, repo_count, commit_count, poc_count.
        config: Optional AppConfig to override default configuration. Takes precedence over github_token.
        github_token: Optional GitHub token to use for API authentication. Ignored if config is provided.

    Returns:
        List of Vulnerability objects.

    Raises:
        ValueError: If filter_expr is invalid or contains syntax errors.
    """
    # Allow quick token override without creating full AppConfig
    if github_token and not config:
        config = AppConfig(github_token=github_token)

    with _provide_container(config) as container:
        uc = container.list_uc()
        return uc.execute(ecosystem=ecosystem, limit=limit, detailed=detailed, filter_expr=filter_expr)


def detail(id: str, *, config: AppConfig | None = None, github_token: str | None = None) -> Vulnerability | None:
    """Return a single detailed vulnerability by selector (e.g., GHSA-..., CVE-...).

    Args:
        id: Vulnerability identifier (GHSA-... or CVE-...).
        config: Optional AppConfig to override default configuration. Takes precedence over github_token.
        github_token: Optional GitHub token to use for API authentication. Ignored if config is provided.

    Returns:
        Vulnerability object if found, None otherwise.
    """
    # Allow quick token override without creating full AppConfig
    if github_token and not config:
        config = AppConfig(github_token=github_token)

    with _provide_container(config) as container:
        uc = container.detail_uc()
        return uc.execute(id)


def dump(id: str, *, config: AppConfig | None = None, github_token: str | None = None) -> list[dict]:
    """Return raw JSON payloads for the id across configured providers.

    Args:
        id: Vulnerability identifier (GHSA-... or CVE-...).
        config: Optional AppConfig to override default configuration. Takes precedence over github_token.
        github_token: Optional GitHub token to use for API authentication. Ignored if config is provided.

    Returns:
        List of raw JSON dictionaries from each configured provider.
    """
    # Allow quick token override without creating full AppConfig
    if github_token and not config:
        config = AppConfig(github_token=github_token)

    with _provide_container(config) as container:
        uc = container.dump_uc()
        return uc.execute(id)


def clear_cache(prefix: str | None = None, *, config: AppConfig | None = None) -> None:
    """Clear caches. Without prefix, clears all. With prefix, clears only matching keys (e.g., 'osv:', 'gh_repo:').

    Args:
        prefix: Optional cache key prefix to clear (e.g., 'osv', 'gh_repo'). If None, clears all cache.
        config: Optional AppConfig to override default configuration (mainly for custom cache_dir).
    """
    with _provide_container(config) as container:
        uc = container.clear_cache_uc()
        uc.execute(prefix=prefix)


def ingest(ecosystems: Sequence[str], *, force: bool = False, config: AppConfig | None = None) -> dict[str, int]:
    """Ingest vulnerability data for specified ecosystems.

    Args:
        ecosystems: List of ecosystem names to ingest (e.g., ['npm', 'pypi', 'go']).
        force: If True, re-download and re-index even if cache exists. Default is False.
        config: Optional AppConfig to override default configuration (mainly for custom cache_dir).

    Returns:
        Dictionary mapping ecosystem names to the number of entries ingested.
        Example: {'npm': 1234, 'pypi': 567}
    """
    with _provide_container(config) as container:
        index = container.index()
        results = {}
        for eco in ecosystems:
            if not force:
                existing = index.list(ecosystem=eco, limit=1)
                if len(existing) > 0:
                    results[eco] = 0  # Skip, already ingested
                    continue
            count = index.ingest_zip(eco)
            results[eco] = count
        return results


__all__ = [
    "AppConfig",
    "list_vulnerabilities",
    "detail",
    "dump",
    "clear_cache",
    "ingest",
]


