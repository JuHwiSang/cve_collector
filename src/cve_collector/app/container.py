from __future__ import annotations

from dependency_injector import containers, providers

from ..core.services.composite_enricher import CompositeEnricher
from ..core.usecases.clear_cache import ClearCacheUseCase
from ..core.usecases.list_vulnerabilities import ListVulnerabilitiesUseCase
from ..core.usecases.detail_vulnerability import DetailVulnerabilityUseCase
from ..core.usecases.raw_dump import RawDumpUseCase
from ..infra.cache_diskcache import DiskCacheAdapter
from ..infra.github_enrichment import GitHubRepoEnricher
from ..infra.osv_adapter import OSVAdapter
from ..infra.rate_limiter import SimpleRateLimiter
from ..infra.http_client import HttpClient
from ..config.loader import load_config
from ..config.types import AppConfig


def cache_resource(app_cfg: AppConfig):
	cache_dir = app_cfg.cache_dir
	with DiskCacheAdapter(
		namespace="github",
		default_ttl_seconds=30 * 24 * 3600,
		base_dir=cache_dir,
	) as cache:
		yield cache


def github_headers(app_cfg: AppConfig) -> dict[str, str]:
	headers: dict[str, str] = {"User-Agent": "cve-collector/1.0"}
	if app_cfg.github_token:
		headers["Authorization"] = f"Bearer {app_cfg.github_token}"
		headers["Accept"] = "application/vnd.github+json"
		headers["X-GitHub-Api-Version"] = "2022-11-28"
	return headers


class Container(containers.DeclarativeContainer):
	config = providers.Configuration()

	app_config = providers.Callable(load_config)

	cache = providers.Resource(cache_resource, app_config)

	rate_limiter = providers.Factory(SimpleRateLimiter, rps=1.5)

	http_client = providers.Factory(HttpClient)
	github_http_client = providers.Factory(HttpClient, base_headers=providers.Callable(github_headers, app_config))

	index = providers.Factory(OSVAdapter, cache=cache, http_client=http_client)

	enrichers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
		providers.Factory(GitHubRepoEnricher, cache=cache, http_client=github_http_client, app_config=app_config),
	)

	raw_providers = providers.List(
		providers.Factory(GitHubRepoEnricher, cache=cache, http_client=github_http_client, app_config=app_config),
	)

	composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

	list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
	detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
	raw_uc = providers.Factory(RawDumpUseCase, providers=raw_providers)
	clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)


