from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Sequence

from .app.container import Container
from .core.domain.models import Vulnerability


@contextmanager
def _provide_container() -> Iterator[Container]:
    container = Container()
    container.init_resources()
    try:
        yield container
    finally:
        container.shutdown_resources()


def list_vulnerabilities(*, ecosystem: str | None = None, limit: int | None = None, detailed: bool = False, filter_expr: str | None = None) -> Sequence[Vulnerability]:
    """Return a list of vulnerabilities. When detailed=True, items are enriched via configured enrichers.

    Args:
        ecosystem: Ecosystem name (e.g., npm). If None, lists all ecosystems.
        limit: Maximum number of results to return. If None, returns all results.
        detailed: If True, enriches items with additional metadata (GitHub stars, size, etc.).
        filter_expr: Filter expression using Python syntax. Examples: 'stars > 1000', 'severity == "HIGH"', 'has_cve and stars > 500'.
                    Filter variables: ghsa_id, cve_id, has_cve, severity, summary, description, details,
                    published_at, modified_at, ecosystem, repo_slug, stars, size_bytes, repo_count, commit_count, poc_count.

    Returns:
        List of Vulnerability objects.

    Raises:
        ValueError: If filter_expr is invalid or contains syntax errors.
    """
    with _provide_container() as container:
        uc = container.list_uc()
        return uc.execute(ecosystem=ecosystem, limit=limit, detailed=detailed, filter_expr=filter_expr)


def detail(id: str) -> Vulnerability | None:
    """Return a single detailed vulnerability by selector (e.g., GHSA-..., CVE-...)."""
    with _provide_container() as container:
        uc = container.detail_uc()
        return uc.execute(id)


def dump(id: str) -> list[dict]:
    """Return raw JSON payloads for the id across configured providers."""
    with _provide_container() as container:
        uc = container.dump_uc()
        return uc.execute(id)


def clear_cache(prefix: str | None = None) -> None:
    """Clear caches. Without prefix, clears all. With prefix, clears only matching keys (e.g., 'osv:', 'gh_repo:')."""
    with _provide_container() as container:
        uc = container.clear_cache_uc()
        uc.execute(prefix=prefix)


def ingest(ecosystems: Sequence[str], *, force: bool = False) -> dict[str, int]:
    """Ingest vulnerability data for specified ecosystems.

    Args:
        ecosystems: List of ecosystem names to ingest (e.g., ['npm', 'pypi', 'go']).
        force: If True, re-download and re-index even if cache exists. Default is False.

    Returns:
        Dictionary mapping ecosystem names to the number of entries ingested.
        Example: {'npm': 1234, 'pypi': 567}
    """
    with _provide_container() as container:
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
    "list_vulnerabilities",
    "detail",
    "dump",
    "clear_cache",
    "ingest",
]


