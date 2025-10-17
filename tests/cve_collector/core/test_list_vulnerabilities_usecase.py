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
    assert "[enriched]" in result[0].summary


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
