from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Optional

from .enums import Severity


@dataclass(frozen=True)
class Repository:
    platform: Optional[str] = None  # e.g., "github"
    owner: Optional[str] = None
    name: Optional[str] = None
    star_count: Optional[int] = None

    @property
    def slug(self) -> Optional[str]:
        if self.owner and self.name:
            return f"{self.owner}/{self.name}"
        return None

    @property
    def url(self) -> Optional[str]:
        if self.platform == "github" and self.slug:
            return f"https://github.com/{self.slug}"
        return None

    def commit_url(self, commit_hash: str) -> Optional[str]:
        base = self.url
        if base and commit_hash:
            return f"{base}/commit/{commit_hash}"
        return None

    @staticmethod
    def from_github(owner: str, name: str, *, stars: Optional[int] = None) -> "Repository":
        return Repository(platform="github", owner=owner, name=name, star_count=stars)


@dataclass(frozen=True)
class Commit:
    repo: Repository
    hash: str

    @property
    def short_hash(self) -> str:
        return self.hash[:12] if self.hash else ""

    @property
    def url(self) -> Optional[str]:
        return self.repo.commit_url(self.hash)


@dataclass(frozen=True)
class Vulnerability:
    ghsa_id: str
    cve_id: Optional[str] = None

    summary: Optional[str] = None
    description: Optional[str] = None

    severity: Optional[Severity] = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None

    repositories: tuple[Repository, ...] = field(default_factory=tuple)
    commits: tuple[Commit, ...] = field(default_factory=tuple)
    poc_urls: tuple[str, ...] = field(default_factory=tuple)

    extra: dict[str, object] = field(default_factory=dict, compare=False)

    def with_updates(self, **kwargs) -> "Vulnerability":
        return replace(self, **kwargs)


