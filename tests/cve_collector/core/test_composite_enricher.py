from __future__ import annotations

from typing import Iterable

from cve_collector.core.domain.models import Vulnerability
from cve_collector.core.services.composite_enricher import CompositeEnricher
from cve_collector.core.ports.enrich_port import VulnerabilityEnrichmentPort


class AddSuffixEnricher(VulnerabilityEnrichmentPort):
    def __init__(self, suffix: str) -> None:
        self._suffix = suffix

    def enrich(self, v: Vulnerability) -> Vulnerability:
        return v.with_updates(summary=(v.summary or "") + self._suffix)

    def enrich_many(self, items: Iterable[Vulnerability]):
        for v in items:
            yield self.enrich(v)


def test_composite_enricher_applies_in_order():
    v = Vulnerability(ghsa_id="GHSA-1", summary="A")
    enricher = CompositeEnricher([AddSuffixEnricher("-B"), AddSuffixEnricher("-C")])
    out = enricher.enrich(v)
    assert out.summary == "A-B-C"


