from __future__ import annotations

from cve_collector.core.domain.models import Commit, Repository, Vulnerability
from cve_collector.core.domain.enums import Severity


def test_repository_urls():
    repo = Repository.from_github("owner", "repo", stars=42, size_bytes=1024000, ecosystem="npm")
    assert repo.slug == "owner/repo"
    assert repo.url == "https://github.com/owner/repo"
    assert repo.commit_url("abcd1234") == "https://github.com/owner/repo/commit/abcd1234"
    assert repo.star_count == 42
    assert repo.size_bytes == 1024000
    assert repo.ecosystem == "npm"


def test_commit_url_and_short_hash():
    repo = Repository.from_github("o", "r")
    c = Commit(repo=repo, hash="0123456789abcdef")
    assert c.short_hash == "0123456789ab"
    assert c.url == "https://github.com/o/r/commit/0123456789abcdef"


def test_vulnerability_with_updates():
    v = Vulnerability(ghsa_id="GHSA-xxxx-yyyy-zzzz", summary="s")
    v2 = v.with_updates(summary="s2", severity=Severity.HIGH)
    assert v.summary == "s"
    assert v2.summary == "s2"
    assert v2.severity == Severity.HIGH


