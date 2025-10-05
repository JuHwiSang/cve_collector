from __future__ import annotations

from typing import Protocol


class RawProviderPort(Protocol):
    def get_raw(self, selector: str) -> dict | None:
        """Return raw JSON payload for the given selector (e.g., GHSA-..., CVE-...).

        Implementations should fetch and return a JSON-serializable mapping.
        """
        ...


