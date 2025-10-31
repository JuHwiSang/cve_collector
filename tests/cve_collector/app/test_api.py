from __future__ import annotations

import pytest

from cve_collector.app.api import CveCollectorClient
from cve_collector.core.domain.models import Vulnerability, Repository, Severity


@pytest.fixture
def client():
    """Create a client instance for testing."""
    with CveCollectorClient() as c:
        yield c


def test_list_vulnerabilities_with_skip(client):
    """Test list_vulnerabilities with skip parameter."""
    # This is an integration test - requires npm ecosystem to be ingested
    # First, ensure we have some data
    try:
        client.ingest(["npm"])
    except Exception:
        pass  # May already be ingested

    # Get first 10
    first_batch = client.list_vulnerabilities(ecosystem="npm", limit=10)

    # Get next 10 (skip first 10)
    second_batch = client.list_vulnerabilities(ecosystem="npm", limit=10, skip=10)

    # They should be different
    if len(first_batch) == 10 and len(second_batch) > 0:
        first_ids = {v.ghsa_id for v in first_batch}
        second_ids = {v.ghsa_id for v in second_batch}
        # No overlap between batches
        assert first_ids.isdisjoint(second_ids)


def test_list_vulnerabilities_skip_with_filter(client):
    """Test skip works with filter."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get filtered results without skip
    all_filtered = client.list_vulnerabilities(
        ecosystem="npm",
        filter_expr="has_cve",
        limit=10
    )

    # Get filtered results with skip=5
    skipped_filtered = client.list_vulnerabilities(
        ecosystem="npm",
        filter_expr="has_cve",
        limit=5,
        skip=5
    )

    # If we have enough results, verify skip worked
    if len(all_filtered) == 10 and len(skipped_filtered) > 0:
        # The skipped results should match the second half of all results
        expected_ids = {v.ghsa_id for v in all_filtered[5:]}
        actual_ids = {v.ghsa_id for v in skipped_filtered}
        assert expected_ids == actual_ids


def test_list_vulnerabilities_skip_exceeds_count(client):
    """Test skip when it exceeds available results."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Skip more than exists
    result = client.list_vulnerabilities(ecosystem="npm", limit=5, skip=999999)

    assert len(result) == 0


def test_list_vulnerabilities_skip_zero(client):
    """Test skip=0 is equivalent to no skip."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    result_no_skip = client.list_vulnerabilities(ecosystem="npm", limit=5)
    result_zero_skip = client.list_vulnerabilities(ecosystem="npm", limit=5, skip=0)

    # Should return same results
    assert len(result_no_skip) == len(result_zero_skip)
    if len(result_no_skip) > 0:
        assert [v.ghsa_id for v in result_no_skip] == [v.ghsa_id for v in result_zero_skip]


def test_list_vulnerabilities_skip_with_detailed(client):
    """Test skip works with detailed enrichment."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get detailed results with skip
    result = client.list_vulnerabilities(
        ecosystem="npm",
        limit=3,
        skip=2,
        detailed=True
    )

    # Should return enriched results (if they have repos/metadata)
    assert len(result) <= 3
    # Just verify it doesn't crash - enrichment might not add stars if repos don't exist


# Tests for list_vulnerabilities_iter

def test_list_vulnerabilities_iter_returns_iterator(client):
    """Test that list_vulnerabilities_iter returns an iterator."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    result = client.list_vulnerabilities_iter(ecosystem="npm", limit=5)

    # Should be an iterator
    assert hasattr(result, '__iter__')
    assert hasattr(result, '__next__')


def test_list_vulnerabilities_iter_can_be_consumed(client):
    """Test that iterator can be consumed in a loop."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    count = 0
    for vuln in client.list_vulnerabilities_iter(ecosystem="npm", limit=5):
        assert isinstance(vuln, Vulnerability)
        count += 1

    assert count <= 5


def test_list_vulnerabilities_iter_vs_list_same_results(client):
    """Test that iter version returns same results as list version."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get results from both methods
    list_result = client.list_vulnerabilities(ecosystem="npm", limit=10)
    iter_result = list(client.list_vulnerabilities_iter(ecosystem="npm", limit=10))

    # Should have same IDs in same order
    if len(list_result) > 0:
        assert [v.ghsa_id for v in list_result] == [v.ghsa_id for v in iter_result]


def test_list_vulnerabilities_iter_with_skip(client):
    """Test iter with skip parameter."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get first batch
    first_batch = list(client.list_vulnerabilities_iter(ecosystem="npm", limit=5))

    # Get second batch with skip
    second_batch = list(client.list_vulnerabilities_iter(ecosystem="npm", limit=5, skip=5))

    # They should be different
    if len(first_batch) == 5 and len(second_batch) > 0:
        first_ids = {v.ghsa_id for v in first_batch}
        second_ids = {v.ghsa_id for v in second_batch}
        assert first_ids.isdisjoint(second_ids)


def test_list_vulnerabilities_iter_with_filter(client):
    """Test iter with filter."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    result = list(client.list_vulnerabilities_iter(
        ecosystem="npm",
        filter_expr="has_cve",
        limit=10
    ))

    # All results should have CVE ID
    if len(result) > 0:
        assert all(v.cve_id is not None for v in result)


def test_list_vulnerabilities_iter_with_detailed(client):
    """Test iter with detailed enrichment."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    result = list(client.list_vulnerabilities_iter(
        ecosystem="npm",
        limit=3,
        detailed=True
    ))

    # Should return enriched results
    assert len(result) <= 3
    # Just verify it doesn't crash


def test_list_vulnerabilities_iter_early_termination(client):
    """Test that iterator can be terminated early."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    iterator = client.list_vulnerabilities_iter(ecosystem="npm", limit=100)

    # Consume only first 3 items
    count = 0
    for vuln in iterator:
        count += 1
        if count >= 3:
            break

    assert count == 3


def test_list_vulnerabilities_iter_with_skip_and_filter(client):
    """Test iter with both skip and filter."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get all filtered
    all_filtered = list(client.list_vulnerabilities_iter(
        ecosystem="npm",
        filter_expr="has_cve",
        limit=10
    ))

    # Get with skip
    skipped = list(client.list_vulnerabilities_iter(
        ecosystem="npm",
        filter_expr="has_cve",
        limit=5,
        skip=5
    ))

    # Verify skip worked
    if len(all_filtered) == 10 and len(skipped) > 0:
        expected_ids = {v.ghsa_id for v in all_filtered[5:]}
        actual_ids = {v.ghsa_id for v in skipped}
        assert expected_ids == actual_ids


def test_list_vulnerabilities_iter_skip_exceeds_count(client):
    """Test iter skip when it exceeds available results."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    result = list(client.list_vulnerabilities_iter(
        ecosystem="npm",
        limit=5,
        skip=999999
    ))

    assert len(result) == 0


def test_list_vulnerabilities_iter_limit_none(client):
    """Test iter with limit=None returns all results."""
    try:
        client.ingest(["npm"])
    except Exception:
        pass

    # Get first 100 with list
    list_result = client.list_vulnerabilities(ecosystem="npm", limit=100)

    # Get same with iter and no limit (but consume max 100 for test)
    iter_result = []
    for i, vuln in enumerate(client.list_vulnerabilities_iter(ecosystem="npm", limit=None)):
        iter_result.append(vuln)
        if i >= 99:  # Stop after 100
            break

    # Should have at least the same results (or iter might have more)
    assert len(iter_result) >= len(list_result)
