from __future__ import annotations

from typing import Protocol, Sequence

from ..domain.models import Vulnerability


class VulnerabilityIndexPort(Protocol):
    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        """Return a GHSA-centric skeleton list (minimal fields).

        Example implementation: parse OSV GHSA entries to construct Vulnerability.
        """
        ...

    def get(self, selector: str) -> Vulnerability | None:
        """Return a single skeleton by a generic selector, or None if not found.

        Core should not assume a specific identifier scheme. Implementations may
        support one or more selector kinds (e.g., GHSA, CVE, DB numeric id, etc.).
        """

    # Backward-compat convenience for current GHSA-centric infra
    def get_by_ghsa(self, ghsa_id: str) -> Vulnerability | None: ...


