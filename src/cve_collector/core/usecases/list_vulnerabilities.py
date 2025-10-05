from __future__ import annotations

from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.list_port import VulnerabilityListPort
from ..ports.enrich_port import VulnerabilityEnrichmentPort


class ListVulnerabilitiesUseCase:
    def __init__(self, index: VulnerabilityListPort, enricher: VulnerabilityEnrichmentPort | None = None) -> None:
        self._index = index
        self._enricher = enricher

    def execute(self, *, ecosystem: str, limit: int | None = None, detailed: bool = False) -> Sequence[Vulnerability]:
        items = self._index.list(ecosystem=ecosystem, limit=limit)
        if not detailed or not self._enricher:
            return items
        # Apply enrichment sequentially; CompositeEnricher may chain multiple enrichers
        return list(self._enricher.enrich_many(items))


