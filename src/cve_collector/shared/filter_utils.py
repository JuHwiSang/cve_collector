from __future__ import annotations

from typing import Sequence, TYPE_CHECKING

from asteval import Interpreter

if TYPE_CHECKING:
    from ..core.domain.models import Vulnerability


def filter_vulnerabilities(vulns: Sequence[Vulnerability], filter_expr: str) -> list[Vulnerability]:
    """Filter vulnerabilities using asteval expression.

    Available variables in filter expression:
    - ghsa_id: str - GHSA identifier
    - cve_id: str | None - CVE identifier
    - has_cve: bool - Whether CVE ID exists
    - severity: str | None - Severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
    - summary: str | None - Summary text
    - description: str | None - Description text
    - details: str | None - Details text
    - published_at: datetime | None - Published timestamp
    - modified_at: datetime | None - Modified timestamp
    - ecosystem: str | None - First repository's ecosystem
    - repo_slug: str | None - First repository's slug (owner/name)
    - stars: int | None - First repository's star count
    - size_bytes: int | None - First repository's size in bytes
    - repo_count: int - Number of repositories
    - commit_count: int - Number of commits
    - poc_count: int - Number of PoC URLs
    """
    aeval = Interpreter()
    filtered = []

    for v in vulns:
        # Extract first repository info (most common case)
        first_repo = v.repositories[0] if v.repositories else None

        # Prepare variables for asteval
        ctx = {
            "ghsa_id": v.ghsa_id,
            "cve_id": v.cve_id,
            "has_cve": v.cve_id is not None,
            "severity": v.severity.name if v.severity else None,
            "summary": v.summary,
            "description": v.description,
            "details": v.details,
            "published_at": v.published_at,
            "modified_at": v.modified_at,
            "ecosystem": first_repo.ecosystem if first_repo else None,
            "repo_slug": first_repo.slug if first_repo else None,
            "stars": first_repo.star_count if first_repo else None,
            "size_bytes": first_repo.size_bytes if first_repo else None,
            "repo_count": len(v.repositories),
            "commit_count": len(v.commits),
            "poc_count": len(v.poc_urls),
        }

        # Set variables in asteval context
        for key, value in ctx.items():
            aeval.symtable[key] = value

        # Evaluate filter expression
        result = aeval(filter_expr)
        if aeval.error:
            error_msg = aeval.error[0].get_error()
            raise ValueError(f"Filter evaluation error: {error_msg}")
        if result:
            filtered.append(v)

    return filtered
