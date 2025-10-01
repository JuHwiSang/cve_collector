from __future__ import annotations

from typing import Iterable, Protocol

from ..domain.models import Vulnerability


class VulnerabilityEnrichmentPort(Protocol):
    def enrich(self, v: Vulnerability) -> Vulnerability:
        """Return a new Vulnerability with enriched fields (repositories/commits/poc_urls)."""
        ...

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:  # pragma: no cover - simple passthrough
        for v in items:
            yield self.enrich(v)


