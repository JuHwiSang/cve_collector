from __future__ import annotations

from cve_collector.shared.utils import (
    is_poc_url,
    parse_github_commit_url,
    parse_github_repo_url,
)


def test_parse_github_repo_url():
    assert parse_github_repo_url("https://github.com/a/b") == ("a", "b")
    assert parse_github_repo_url("https://github.com/a") is None


def test_parse_github_commit_url():
    assert parse_github_commit_url("https://github.com/a/b/commit/abcdef") == ("a", "b", "abcdef")
    assert parse_github_commit_url("https://github.com/a/b/commit/zzz") is None


def test_is_poc_url():
    assert is_poc_url("https://example.com/poc/123")
    assert not is_poc_url("https://example.com/docs")


