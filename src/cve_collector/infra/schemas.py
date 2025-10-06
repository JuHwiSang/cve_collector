from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class OsvVulnerability(BaseModel):
	id: str
	aliases: list[str] | None = None
	summary: str | None = None
	details: str | None = None
	modified: str | None = None
	published: str | None = None
	severity: list["OsvSeverity"] | None = None
	references: list["OsvReference"] | None = None
	database_specific: Optional["OsvDatabaseSpecific"] = None


class GhIdentifier(BaseModel):
	type: str
	value: str


class GhReference(BaseModel):
	url: str


class GitHubAdvisory(BaseModel):
    severity: Optional[str] = None
    identifiers: list[GhIdentifier] | None = None
    # GitHub REST can return references as strings or objects depending on endpoint/version
    references: list[GhReference | str] | None = None


class OsvSeverity(BaseModel):
	type: str
	score: str | float


class OsvReference(BaseModel):
	type: str | None = None
	url: str


class OsvDatabaseSpecific(BaseModel):
	severity: Optional[str] = None
	nvd_published_at: Optional[str] = None
	cwe_ids: list[str] | None = None
	github_reviewed: Optional[bool] = None
	github_reviewed_at: Optional[str] = None


