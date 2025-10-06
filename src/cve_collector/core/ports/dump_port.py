from __future__ import annotations

from typing import Protocol


class DumpProviderPort(Protocol):
    def dump(self, id: str) -> dict | None:
        """Return raw JSON payload for the given id (e.g., GHSA-..., CVE-...).

        Implementations should fetch and return a JSON-serializable mapping.
        """
        ...


