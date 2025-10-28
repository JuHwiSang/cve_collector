from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Application configuration with automatic environment variable loading.

    All settings can be overridden via environment variables with the CVE_COLLECTOR_ prefix.
    For example:
        - CVE_COLLECTOR_GITHUB_TOKEN=ghp_xxx
        - CVE_COLLECTOR_CACHE_DIR=/path/to/cache
        - CVE_COLLECTOR_GITHUB_CACHE_TTL_DAYS=30
        - CVE_COLLECTOR_OSV_CACHE_TTL_DAYS=7

    Alternatively, settings can be provided programmatically when creating the Container:
        container = Container()
        container.app_config.override(AppConfig(github_token="ghp_xxx"))
    """

    model_config = SettingsConfigDict(
        env_prefix="CVE_COLLECTOR_",
        case_sensitive=False,
        extra="forbid",
    )

    github_token: Optional[str] = Field(
        default=None,
        description="GitHub personal access token for authenticated API access (increases rate limit from 60/hour to 5000/hour)",
    )

    cache_dir: Optional[Path] = Field(
        default=None,
        description="Custom cache directory path. If None, uses platformdirs.user_cache_dir('cve-collector')",
    )

    github_cache_ttl_days: int = Field(
        default=30,
        ge=1,
        description="TTL for GitHub repository metadata cache in days",
    )

    osv_cache_ttl_days: int = Field(
        default=7,
        ge=1,
        description="TTL for OSV vulnerability data cache in days",
    )
