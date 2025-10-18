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


def list_vulnerabilities(*, ecosystem: str = "npm", limit: int | None = None, detailed: bool = False) -> Sequence[Vulnerability]:
    """Return a list of vulnerabilities. When detailed=True, items are enriched via configured enrichers."""
    with _provide_container() as container:
        uc = container.list_uc()
        return uc.execute(ecosystem=ecosystem, limit=limit, detailed=detailed)


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


__all__ = [
    "list_vulnerabilities",
    "detail",
    "dump",
    "clear_cache",
]


