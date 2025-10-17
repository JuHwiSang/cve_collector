from __future__ import annotations

from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.index_port import VulnerabilityIndexPort
from ..ports.enrich_port import VulnerabilityEnrichmentPort
from ...shared.filter_utils import filter_vulnerabilities


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
        # If no filter and no enrichment needed, simple pass-through
        if not filter_expr and not detailed:
            return self._index.list(ecosystem=ecosystem, limit=limit)

        # Fetch all skeleton items (lightweight)
        items = self._index.list(ecosystem=ecosystem)

        # Lazy process: enrich and filter one by one until we have enough
        result: list[Vulnerability] = []
        target_limit = limit or float('inf')

        for item in items:
            # Apply enrichment if detailed
            if detailed and self._enricher:
                item = self._enricher.enrich(item)

            # Apply filter if provided
            if filter_expr:
                # Filter single item
                filtered = filter_vulnerabilities([item], filter_expr)
                if not filtered:
                    continue  # Skip this item
                item = filtered[0]

            # Add to result
            result.append(item)

            # Stop if we have enough
            if len(result) >= target_limit:
                break

        return result[:int(target_limit)] if limit else result


