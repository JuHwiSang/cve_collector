from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AppConfig:
    github_token: Optional[str]
    cache_dir: Optional[str]
    github_cache_ttl_days: int
    osv_cache_ttl_days: int


