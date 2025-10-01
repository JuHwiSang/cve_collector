from __future__ import annotations

from dependency_injector import containers, providers

from ..core.services.composite_enricher import CompositeEnricher
from ..core.usecases.clear_cache import ClearCacheUseCase
from ..core.usecases.list_vulnerabilities import ListVulnerabilitiesUseCase
from ..core.usecases.show_vulnerability import ShowVulnerabilityUseCase
from ..infra.cache_diskcache import DiskCacheAdapter
from ..infra.github_enrichment import GitHubAdvisoryEnricher
from ..infra.osv_index import OSVIndexAdapter
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


class Container(containers.DeclarativeContainer):
	config = providers.Configuration()

	app_config = providers.Callable(load_config)

	cache = providers.Resource(cache_resource, app_config)

	rate_limiter = providers.Factory(SimpleRateLimiter, rps=1.5)

	http_client = providers.Factory(HttpClient)

	index = providers.Factory(OSVIndexAdapter, cache=cache, http_client=http_client)

	enrichers = providers.List(
		providers.Factory(GitHubAdvisoryEnricher, cache=cache, http_client=http_client),
	)

	composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

	list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index)
	show_uc = providers.Factory(ShowVulnerabilityUseCase, index=index, enricher=composite_enricher)
	clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)


