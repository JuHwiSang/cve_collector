from __future__ import annotations

import logging
from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.index_port import VulnerabilityIndexPort
from ..ports.enrich_port import VulnerabilityEnrichmentPort
from ...shared.filter_utils import filter_vulnerabilities

logger = logging.getLogger(__name__)


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
        logger.info(f"Listing vulnerabilities: ecosystem={ecosystem}, limit={limit}, detailed={detailed}, filter={filter_expr}")

        # If no filter and no enrichment needed, simple pass-through
        if not filter_expr and not detailed:
            logger.debug("Fast path: no enrichment or filtering needed")
            results = self._index.list(ecosystem=ecosystem, limit=limit)
            logger.info(f"Found {len(results)} vulnerabilities")
            return results

        # Fetch all skeleton items (lightweight)
        logger.debug("Fetching all items from index for lazy processing")
        items = self._index.list(ecosystem=ecosystem)
        logger.info(f"Fetched {len(items)} items from index, starting lazy enrichment/filtering")

        # Lazy process: enrich and filter one by one until we have enough
        result: list[Vulnerability] = []
        target_limit = limit or float('inf')
        processed_count = 0

        for item in items:
            processed_count += 1

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

        logger.info(f"Processed {processed_count} items, returned {len(result)} results")
        return result[:int(target_limit)] if limit else result


