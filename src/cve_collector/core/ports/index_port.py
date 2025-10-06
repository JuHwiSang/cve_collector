from __future__ import annotations

from typing import Protocol, Sequence

from ..domain.models import Vulnerability


class VulnerabilityIndexPort(Protocol):
    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        """Return a GHSA-centric skeleton list (minimal fields).

        Example implementation: parse OSV GHSA entries to construct Vulnerability.
        """
        ...

    def get(self, id: str) -> Vulnerability | None:
        """Return a single skeleton by a generic id, or None if not found.

        Core should not assume a specific identifier scheme. Implementations may
        support one or more id kinds (e.g., GHSA, CVE, DB numeric id, etc.).
        """


