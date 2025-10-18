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
from ..infra.rate_limiter import SlidingWindowRateLimiter
from ..infra.http_client import HttpClient
from ..config.loader import load_config
from ..config.types import AppConfig
from ..config.token_utils import hash_token_for_namespace


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
		headers["Accept"] = "application/vnd.github.v3+json"
	return headers


def create_github_rate_limiter_namespace(app_cfg: AppConfig) -> str | None:
	"""Create namespace for GitHub rate limiter based on token hash.

	Returns None if no token configured (falls back to memory-only mode).
	"""
	if not app_cfg.github_token:
		return None
	return hash_token_for_namespace(app_cfg.github_token, prefix_length=12)


class Container(containers.DeclarativeContainer):
	config = providers.Configuration()

	app_config = providers.Callable(load_config)

	cache = providers.Resource(cache_resource, app_config)

	# GitHub API limit: 5000 requests/hour for authenticated users
	# Using conservative 4500/hour to leave safety margin
	# With persistent cache + namespace for cross-process rate limiting
	github_rate_limiter_namespace = providers.Callable(create_github_rate_limiter_namespace, app_config)

	rate_limiter = providers.Factory(
		SlidingWindowRateLimiter,
		max_requests=4500,
		window_seconds=3600.0,
		cache=cache,
		namespace=github_rate_limiter_namespace,
	)

	http_client = providers.Factory(HttpClient)
	github_http_client = providers.Factory(
		HttpClient,
		base_headers=providers.Callable(github_headers, app_config),
		rate_limiter=rate_limiter
	)

	index = providers.Factory(OSVAdapter, cache=cache, http_client=http_client)

	enrichers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
		providers.Factory(GitHubRepoEnricher, cache=cache, http_client=github_http_client, app_config=app_config),
	)

	dump_providers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
	)

	composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

	list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
	detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
	dump_uc = providers.Factory(RawDumpUseCase, providers=dump_providers)
	clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)


