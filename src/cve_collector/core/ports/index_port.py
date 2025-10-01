from __future__ import annotations

from typing import Protocol, Sequence

from ..domain.models import Vulnerability


class VulnerabilityIndexPort(Protocol):
    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        """Return a GHSA-centric skeleton list (minimal fields).

        Example implementation: parse OSV GHSA entries to construct Vulnerability.
        """
        ...

    def get_by_ghsa(self, ghsa_id: str) -> Vulnerability | None:
        """Return a single skeleton by GHSA id, or None if not found."""


