from __future__ import annotations

import os

from .types import AppConfig


def load_config() -> AppConfig:
    return AppConfig(
        github_token=os.getenv("GITHUB_TOKEN"),
        cache_dir=os.getenv("CVE_COLLECTOR_CACHE_DIR"),
        github_cache_ttl_days=int(os.getenv("CVE_GITHUB_TTL_DAYS", "30")),
        osv_cache_ttl_days=int(os.getenv("CVE_OSV_TTL_DAYS", "7")),
    )


