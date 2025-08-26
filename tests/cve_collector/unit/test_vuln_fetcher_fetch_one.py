import pytest
from datetime import date

from cve_collector.cve_collector import CVECollector


def test_collect_one_raises_on_osv_failure(monkeypatch):
    vf = CVECollector(github_token="test")

    def fail_fetch(_identifier: str):
        raise RuntimeError("boom")

    monkeypatch.setattr(vf.osv_client, "fetch_vulnerability_details", fail_fetch)

    with pytest.raises(ValueError) as ei:
        vf.collect_one("CVE-2099-0001")

    assert "OSV 조회 실패" in str(ei.value)


