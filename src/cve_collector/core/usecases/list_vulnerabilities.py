from __future__ import annotations

from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.index_port import VulnerabilityIndexPort
from ..ports.enrich_port import VulnerabilityEnrichmentPort


class ListVulnerabilitiesUseCase:
    def __init__(self, index: VulnerabilityIndexPort, enricher: VulnerabilityEnrichmentPort | None = None) -> None:
        self._index = index
        self._enricher = enricher

    def execute(
        self,
        *,
        ecosystem: str | None = None,
        limit: int | None = None,
        detailed: bool = False,
        filter_expr: str | None = None,
    ) -> Sequence[Vulnerability]:
        # Pass filter to index layer so it's applied before limit
        items = self._index.list(ecosystem=ecosystem, limit=limit, filter_expr=filter_expr)

        # Apply enrichment if detailed
        if detailed and self._enricher:
            items = list(self._enricher.enrich_many(items))

        return items


