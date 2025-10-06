from __future__ import annotations

from typing import Sequence

from ..ports.dump_port import DumpProviderPort


class RawDumpUseCase:
    def __init__(self, providers: Sequence[DumpProviderPort]) -> None:
        self._providers = tuple(providers)

    def execute(self, id: str) -> list[dict]:
        results: list[dict] = []
        for p in self._providers:
            payload = p.dump(id)
            if payload is not None:
                results.append(payload)
        return results


