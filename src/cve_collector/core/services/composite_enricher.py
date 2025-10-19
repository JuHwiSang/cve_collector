from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.enrich_port import VulnerabilityEnrichmentPort

logger = logging.getLogger(__name__)


class CompositeEnricher:
    def __init__(self, enrichers: Sequence[VulnerabilityEnrichmentPort]) -> None:
        self._enrichers = tuple(enrichers)
        logger.debug(f"Initialized CompositeEnricher with {len(self._enrichers)} enrichers")

    def enrich(self, v: Vulnerability) -> Vulnerability:
        logger.debug(f"Enriching {v.ghsa_id} with {len(self._enrichers)} enrichers")
        enriched = v
        for enricher in self._enrichers:
            enricher_name = enricher.__class__.__name__
            logger.debug(f"Applying {enricher_name} to {v.ghsa_id}")
            enriched = enricher.enrich(enriched)
        return enriched

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        for v in items:
            yield self.enrich(v)


