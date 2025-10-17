from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class OsvSeverity(BaseModel):
	"""취약점 심각도 정보 (예: CVSS)"""
	type: str
	score: str | float


class OsvPackage(BaseModel):
	"""영향을 받는 패키지 정보"""
	ecosystem: str
	name: str
	purl: Optional[str] = None


class OsvEvent(BaseModel):
	"""버전 범위의 시작 또는 끝을 정의하는 이벤트"""
	introduced: Optional[str] = None
	fixed: Optional[str] = None
	last_affected: Optional[str] = None
	limit: Optional[str] = None


class OsvRange(BaseModel):
	"""영향을 받는 버전 범위"""
	type: str
	repo: Optional[str] = None
	events: list[OsvEvent]


class OsvAffected(BaseModel):
	"""취약점의 영향을 받는 패키지 및 버전 정보"""
	package: OsvPackage
	ranges: Optional[list[OsvRange]] = None
	versions: Optional[list[str]] = None
	ecosystem_specific: Optional[dict[str, Any]] = None
	database_specific: Optional[dict[str, Any]] = None


class OsvReference(BaseModel):
	"""관련 외부 참조 링크"""
	type: str | None = None
	url: str


class OsvDatabaseSpecific(BaseModel):
	"""데이터베이스별 추가 정보"""
	severity: Optional[str] = None
	nvd_published_at: Optional[str] = None
	cwe_ids: list[str] | None = None
	github_reviewed: Optional[bool] = None
	github_reviewed_at: Optional[str] = None


class OsvVulnerability(BaseModel):
	"""OSV 스키마의 최상위 모델"""
	schema_version: Optional[str] = Field(None, alias='schema_version')
	id: str
	modified: Optional[str] = None  # Made optional for backward compatibility with tests
	published: Optional[str] = None
	withdrawn: Optional[str] = None
	aliases: Optional[list[str]] = None
	related: Optional[list[str]] = None
	summary: Optional[str] = None
	details: Optional[str] = None
	severity: Optional[list[OsvSeverity]] = None
	affected: list[OsvAffected] | None = None
	references: Optional[list[OsvReference]] = None
	database_specific: Optional[OsvDatabaseSpecific] = None


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


