from __future__ import annotations

from typing import Iterable
from datetime import datetime

import pytest

from cve_collector.core.domain.models import Vulnerability, Repository, Severity
from cve_collector.core.usecases.list_vulnerabilities import ListVulnerabilitiesUseCase
from cve_collector.core.ports.index_port import VulnerabilityIndexPort
from cve_collector.core.ports.enrich_port import VulnerabilityEnrichmentPort


class FakeIndex(VulnerabilityIndexPort):
    def __init__(self, vulns: list[Vulnerability]) -> None:
        self._vulns = vulns

    def list(self, *, ecosystem: str | None = None, limit: int | None = None):
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
    def enrich(self, v: Vulnerability) -> Vulnerability:
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


def test_filter_by_severity(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='severity == "HIGH"')

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-1"


def test_filter_by_stars(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='stars > 1000')

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-2"


def test_filter_by_has_cve(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='has_cve')

    assert len(result) == 3
    assert all(v.cve_id is not None for v in result)


def test_filter_by_ecosystem(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='ecosystem == "npm"')

    assert len(result) == 3
    assert all(v.repositories[0].ecosystem == "npm" for v in result)


def test_filter_complex_expression(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='has_cve and stars > 500')

    assert len(result) == 2
    assert result[0].ghsa_id == "GHSA-1"
    assert result[1].ghsa_id == "GHSA-2"


def test_filter_with_in_operator(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='severity in ["CRITICAL", "HIGH"]')

    assert len(result) == 2
    assert result[0].severity == Severity.HIGH
    assert result[1].severity == Severity.CRITICAL


def test_filter_invalid_expression(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    with pytest.raises(ValueError, match="Filter evaluation error"):
        uc.execute(filter_expr='invalid syntax !')


def test_filter_with_enrichment(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesUseCase(index, enricher)

    # Filter should work on enriched data
    result = uc.execute(detailed=True, filter_expr='severity == "HIGH"')

    assert len(result) == 1
    assert result[0].summary and "[enriched]" in result[0].summary # type: ignore


def test_filter_repo_count(sample_vulnerabilities):
    # Add a vulnerability with multiple repos
    multi_repo_vuln = Vulnerability(
        ghsa_id="GHSA-5",
        repositories=(
            Repository.from_github("owner5", "repo5", ecosystem="npm"),
            Repository.from_github("owner6", "repo6", ecosystem="npm"),
        ),
    )
    vulns = sample_vulnerabilities + [multi_repo_vuln]

    index = FakeIndex(vulns)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute(filter_expr='repo_count > 1')

    assert len(result) == 1
    assert result[0].ghsa_id == "GHSA-5"


def test_no_filter_returns_all(sample_vulnerabilities):
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    result = uc.execute()

    assert len(result) == 4


def test_filter_applied_before_limit(sample_vulnerabilities):
    """Test that filter is applied before limit to ensure correct result count."""
    index = FakeIndex(sample_vulnerabilities)
    uc = ListVulnerabilitiesUseCase(index)

    # Without filter, limit=2 returns first 2
    result_no_filter = uc.execute(limit=2)
    assert len(result_no_filter) == 2

    # With filter, should get 2 HIGH/CRITICAL items even if they're not the first 2
    result_with_filter = uc.execute(filter_expr='severity in ["HIGH", "CRITICAL"]', limit=2)
    assert len(result_with_filter) == 2
    assert all(v.severity in [Severity.HIGH, Severity.CRITICAL] for v in result_with_filter)


def test_lazy_enrichment_with_filter_and_limit(sample_vulnerabilities):
    """Test that lazy enrichment and filtering work correctly with limit."""
    # Create a larger dataset
    large_dataset = sample_vulnerabilities * 30  # 120 items

    index = FakeIndex(large_dataset)
    enricher = FakeEnricher()
    uc = ListVulnerabilitiesUseCase(index, enricher)

    # Filter for HIGH severity with enrichment and limit
    result = uc.execute(detailed=True, filter_expr='severity == "HIGH"', limit=5)

    # Should get exactly 5 HIGH severity items
    assert len(result) == 5
    assert all(v.severity == Severity.HIGH for v in result)
    # All should be enriched
    assert all(v.summary and "[enriched]" in v.summary for v in result)
