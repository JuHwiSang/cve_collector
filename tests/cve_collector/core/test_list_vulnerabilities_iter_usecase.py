from __future__ import annotations

from typing import Iterable
from datetime import datetime

import pytest

from cve_collector.core.domain.models import Vulnerability, Repository, Severity
from cve_collector.core.usecases.list_vulnerabilities_iter import ListVulnerabilitiesIterUseCase
from cve_collector.core.ports.index_port import VulnerabilityIndexPort
from cve_collector.core.ports.enrich_port import VulnerabilityEnrichmentPort


class FakeIndex(VulnerabilityIndexPort):
    def __init__(self, vulns: list[Vulnerability]) -> None:
        self._vulns = vulns
        self.list_call_count = 0

    def list(self, *, ecosystem: str | None = None, limit: int | None = None):
        self.list_call_count += 1
        items = self._vulns
        if ecosystem:
            items = [v for v in items if any(r.ecosystem == ecosystem for r in v.repositories)]

        # Apply limit if specified
        if limit:
            items = items[:limit]
        return items

    def get(self, id: str):
        raise NotImplementedError

    def ingest_zip(self, ecosystem: str) -> int:
        raise NotImplementedError


class FakeEnricher(VulnerabilityEnrichmentPort):
    def __init__(self) -> None:
        self.enrich_call_count = 0

    def enrich(self, v: Vulnerability) -> Vulnerability:
        # Track enrichment calls
        self.enrich_call_count += 1
        # Add a fake enrichment marker
        return v.with_updates(summary=(v.summary or "") + " [enriched]")

    def enrich_many(self, items: Iterable[Vulnerability]):
        for v in items:
            yield self.enrich(v)


@pytest.fixture
def sample_vulnerabilities():
    return [
        Vulnerability(
            ghsa_id="GHSA-1",
            cve_id="CVE-2024-0001",
            severity=Severity.HIGH,
            summary="High severity vuln",
            repositories=(Repository.from_github("owner1", "repo1", stars=1000, ecosystem="npm"),),
        ),
        Vulnerability(
            ghsa_id="GHSA-2",
            cve_id="CVE-2024-0002",
            severity=Severity.CRITICAL,
            summary="Critical severity vuln",
            repositories=(Repository.from_github("owner2", "repo2", stars=5000, ecosystem="npm"),),
        ),
        Vulnerability(
            ghsa_id="GHSA-3",
            cve_id=None,
            severity=Severity.MEDIUM,
            summary="Medium severity vuln",
            repositories=(Repository.from_github("owner3", "repo3", stars=100, ecosystem="pypi"),),
        ),
        Vulnerability(
            ghsa_id="GHSA-4",
            cve_id="CVE-2024-0004",
            severity=Severity.LOW,
            summary="Low severity vuln",
            repositories=(Repository.from_github("owner4", "repo4", stars=50, ecosystem="npm"),),
        ),
    ]


def test_returns_iterator(sample_vulnerabilities):
    """Test that execute returns an iterator, not a list."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = uc.execute()

    # Should be an iterator/generator
    assert hasattr(result, '__iter__')
    assert hasattr(result, '__next__')


def test_iter_filter_by_severity(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='severity == "HIGH"'))

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-1"


def test_iter_filter_by_stars(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='stars > 1000'))

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-2"


def test_iter_filter_by_has_cve(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='has_cve'))

    assert len(result) == 3
    assert all(v.cve_id is not None for v in result)


def test_iter_filter_by_ecosystem(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='ecosystem == "npm"'))

    assert len(result) == 3
    assert all(v.repositories[0].ecosystem == "npm" for v in result)


def test_iter_filter_complex_expression(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='has_cve and stars > 500'))

    assert len(result) == 2
    assert result[0].ghsa_id == "GHSA-1"
    assert result[1].ghsa_id == "GHSA-2"


def test_iter_filter_with_in_operator(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='severity in ["CRITICAL", "HIGH"]'))

    assert len(result) == 2
    assert result[0].severity == Severity.HIGH
    assert result[1].severity == Severity.CRITICAL


def test_iter_filter_invalid_expression(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    with pytest.raises(ValueError, match="Filter evaluation error"):
        # Must consume iterator to trigger evaluation
        list(uc.execute(filter_expr='invalid syntax !'))


def test_iter_filter_with_enrichment(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Filter should work on enriched data
    result = list(uc.execute(detailed=True, filter_expr='severity == "HIGH"'))

    assert len(result) == 1
    assert result[0].summary and "[enriched]" in result[0].summary # type: ignore


def test_iter_no_filter_returns_all(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute())

    assert len(result) == 4


def test_iter_filter_applied_before_limit(sample_vulnerabilities):
    """Test that filter is applied before limit to ensure correct result count."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    # Without filter, limit=2 returns first 2
    result_no_filter = list(uc.execute(limit=2))
    assert len(result_no_filter) == 2

    # With filter, should get 2 HIGH/CRITICAL items even if they're not the first 2
    result_with_filter = list(uc.execute(filter_expr='severity in ["HIGH", "CRITICAL"]', limit=2))
    assert len(result_with_filter) == 2
    assert all(v.severity in [Severity.HIGH, Severity.CRITICAL] for v in result_with_filter)


def test_iter_skip_with_filter(sample_vulnerabilities):
    """Test skip with filter in lazy path."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    # Filter npm (3 results), skip first 1
    result = list(uc.execute(filter_expr='ecosystem == "npm"', skip=1))

    assert len(result) == 2
    assert result[0].ghsa_id == "GHSA-2"
    assert result[1].ghsa_id == "GHSA-4"


def test_iter_skip_with_filter_and_limit(sample_vulnerabilities):
    """Test skip with both filter and limit."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    # Filter npm (3 results), skip 1, limit 1 -> should get GHSA-2
    result = list(uc.execute(filter_expr='ecosystem == "npm"', skip=1, limit=1))

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-2"


def test_iter_skip_with_enrichment(sample_vulnerabilities):
    """Test skip with enrichment in lazy path."""
    index = FakeIndex(sample_vulnerabilities)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Skip first 2 with enrichment
    result = list(uc.execute(detailed=True, skip=2))

    assert len(result) == 2
    assert result[0].ghsa_id == "GHSA-3"
    assert result[1].ghsa_id == "GHSA-4"
    # Should be enriched
    assert all(v.summary and "[enriched]" in v.summary for v in result)


# Iterator-specific tests

def test_iter_lazy_evaluation(sample_vulnerabilities):
    """Test that iterator evaluates lazily - enrichment only happens on consumption."""
    index = FakeIndex(sample_vulnerabilities)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Get iterator but don't consume it
    iterator = uc.execute(detailed=True)

    # Generator not started yet - no calls made
    assert index.list_call_count == 0
    assert enricher.enrich_call_count == 0

    # Consume one item - this starts the generator
    next(iterator)
    # Now index should be called once, and first item enriched
    assert index.list_call_count == 1
    assert enricher.enrich_call_count == 1

    # Consume another - only one more enrichment
    next(iterator)
    assert index.list_call_count == 1  # Index still called only once
    assert enricher.enrich_call_count == 2


def test_iter_early_termination(sample_vulnerabilities):
    """Test that iterator can be terminated early without processing all items."""
    # Create larger dataset
    large_dataset = sample_vulnerabilities * 100  # 400 items

    index = FakeIndex(large_dataset)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Request all items but consume only 5
    iterator = uc.execute(detailed=True)
    result = []
    for i, item in enumerate(iterator):
        result.append(item)
        if i >= 4:  # Stop after 5 items
            break

    assert len(result) == 5
    # Only 5 items should be enriched (lazy evaluation)
    assert enricher.enrich_call_count == 5


def test_iter_limit_stops_processing_early(sample_vulnerabilities):
    """Test that limit stops processing early with filter."""
    # Create larger dataset where only some match filter
    large_dataset = sample_vulnerabilities * 50  # 200 items

    index = FakeIndex(large_dataset)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Filter for HIGH severity (50 matches), limit 3
    result = list(uc.execute(detailed=True, filter_expr='severity == "HIGH"', limit=3))

    assert len(result) == 3
    assert all(v.severity == Severity.HIGH for v in result)
    # Should only enrich items until we get 3 matches (plus non-matches along the way)
    # The exact count depends on ordering, but should be much less than 200
    assert enricher.enrich_call_count < 200


def test_iter_can_be_consumed_in_loop(sample_vulnerabilities):
    """Test that iterator can be consumed naturally in a for loop."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    count = 0
    ghsa_ids = []
    for vuln in uc.execute(filter_expr='ecosystem == "npm"'):
        count += 1
        ghsa_ids.append(vuln.ghsa_id)

    assert count == 3
    assert ghsa_ids == ["GHSA-1", "GHSA-2", "GHSA-4"]


def test_iter_can_be_consumed_partially(sample_vulnerabilities):
    """Test that iterator can be consumed partially without error."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    iterator = uc.execute()

    # Get first item
    first = next(iterator)
    assert first.ghsa_id == "GHSA-1"

    # Get second item
    second = next(iterator)
    assert second.ghsa_id == "GHSA-2"

    # Don't consume the rest - should not cause any issues


def test_iter_multiple_consumption_not_possible(sample_vulnerabilities):
    """Test that iterator can only be consumed once."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    iterator = uc.execute()

    # First consumption
    result1 = list(iterator)
    assert len(result1) == 4

    # Second consumption should yield nothing (iterator exhausted)
    result2 = list(iterator)
    assert len(result2) == 0


def test_iter_with_limit_none_returns_all(sample_vulnerabilities):
    """Test that limit=None returns all matching items."""
    large_dataset = sample_vulnerabilities * 50  # 200 items

    index = FakeIndex(large_dataset)
    uc = ListVulnerabilitiesIterUseCase(index)

    result = list(uc.execute(filter_expr='severity == "HIGH"', limit=None))

    assert len(result) == 50  # All HIGH severity items


def test_iter_skip_exceeds_total_count(sample_vulnerabilities):
    """Test skip when it exceeds total result count."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesIterUseCase(index)

    # Skip more than available
    result = list(uc.execute(skip=10))

    assert len(result) == 0


def test_iter_memory_efficient_with_large_dataset(sample_vulnerabilities):
    """Test that iterator doesn't accumulate all results in memory."""
    # Create very large dataset
    large_dataset = sample_vulnerabilities * 1000  # 4000 items

    index = FakeIndex(large_dataset)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesIterUseCase(index, enricher)

    # Process with limit - should only enrich needed items
    result = list(uc.execute(detailed=True, filter_expr='severity == "CRITICAL"', limit=10))

    assert len(result) == 10
    assert all(v.severity == Severity.CRITICAL for v in result)
    # Should process much less than the full dataset
    # We know CRITICAL appears every 4 items, so should process ~40 items to get 10 matches
    assert enricher.enrich_call_count < 100
