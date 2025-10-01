from __future__ import annotations

from collections.abc import Iterable
from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.enrich_port import VulnerabilityEnrichmentPort


class CompositeEnricher:
    def __init__(self, enrichers: Sequence[VulnerabilityEnrichmentPort]) -> None:
        self._enrichers = tuple(enrichers)

    def enrich(self, v: Vulnerability) -> Vulnerability:
        enriched = v
        for enricher in self._enrichers:
            enriched = enricher.enrich(enriched)
        return enriched

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        for v in items:
            yield self.enrich(v)


