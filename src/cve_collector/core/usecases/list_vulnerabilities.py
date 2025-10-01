from __future__ import annotations

from typing import Sequence

from ..domain.models import Vulnerability
from ..ports.index_port import VulnerabilityIndexPort


class ListVulnerabilitiesUseCase:
    def __init__(self, index: VulnerabilityIndexPort) -> None:
        self._index = index

    def execute(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        return self._index.list(ecosystem=ecosystem, limit=limit)


