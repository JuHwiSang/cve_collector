import pytest
from datetime import date

from cve_collector.cve_collector import CVECollector, PostFilterError
from cve_collector.cve import CVE


def _make_cve(**overrides) -> CVE:
    cve = CVE(
        ghsa_id="GHSA-XXXX-YYYY-ZZZZ",
        cve_id="CVE-2099-0001",
        pkg="dummy",
        osv={},
        published_date=date.today(),
        affected_ecosystems=["npm"],
        gh=None,
        repo=None,
        size_kb=None,
        patches=[],
        pocs=[],
        commits=[],
    )
    for key, value in overrides.items():
        setattr(cve, key, value)
    return cve


def test_post_filter_no_repo_raises():
    vf = CVECollector(github_token="test")
    cve = _make_cve(repo=None, patches=[], pocs=[])
    with pytest.raises(PostFilterError) as ei:
        vf._apply_post_filter(cve)
    assert ei.value.code == "no_repo"


def test_post_filter_repo_large_raises():
    vf = CVECollector(github_token="test")
    cve = _make_cve(repo="owner/repo", size_kb=20000, patches=["x"], pocs=[])
    with pytest.raises(PostFilterError) as ei:
        vf._apply_post_filter(cve)
    assert ei.value.code == "repo_large"


def test_post_filter_no_artifacts_raises():
    vf = CVECollector(github_token="test")
    cve = _make_cve(repo="owner/repo", size_kb=100, patches=[], pocs=[])
    with pytest.raises(PostFilterError) as ei:
        vf._apply_post_filter(cve)
    assert ei.value.code == "no_artifacts"


def test_post_filter_passes():
    vf = CVECollector(github_token="test")
    cve = _make_cve(repo="owner/repo", size_kb=100, patches=["https://github.com/owner/repo/commit/abc"], pocs=[])
    ret = vf._apply_post_filter(cve)
    assert ret is cve


