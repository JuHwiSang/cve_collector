from __future__ import annotations

from typing import Sequence

from ..ports.raw_port import RawProviderPort


class RawDumpUseCase:
    def __init__(self, providers: Sequence[RawProviderPort]) -> None:
        self._providers = tuple(providers)

    def execute(self, selector: str) -> list[dict]:
        results: list[dict] = []
        for p in self._providers:
            payload = p.get_raw(selector)
            if payload is not None:
                results.append(payload)
        return results


