from __future__ import annotations

import logging

from dependency_injector import containers, providers
from github import Auth, Github

from ..core.services.composite_enricher import CompositeEnricher
from ..core.usecases.clear_cache import ClearCacheUseCase
from ..core.usecases.list_vulnerabilities import ListVulnerabilitiesUseCase
from ..core.usecases.list_vulnerabilities_iter import ListVulnerabilitiesIterUseCase
from ..core.usecases.detail_vulnerability import DetailVulnerabilityUseCase
from ..core.usecases.raw_dump import RawDumpUseCase
from ..infra.cache_diskcache import DiskCacheAdapter
from ..infra.github_enrichment import GitHubRepoEnricher
from ..infra.osv_adapter import OSVAdapter
from ..infra.http_client import HttpClient
from ..config.settings import AppConfig

logger = logging.getLogger(__name__)


def cache_resource(cache_dir, github_cache_ttl_days):
	cache_dir_str = str(cache_dir) if cache_dir else None
	logger.info(f"Initializing cache at: {cache_dir_str or 'default user cache directory'}")
	with DiskCacheAdapter(
		namespace="github",
		default_ttl_seconds=github_cache_ttl_days * 24 * 3600,
		base_dir=cache_dir_str,
	) as cache:
		logger.debug("Cache initialized successfully")
		yield cache
	logger.debug("Cache closed")


def github_client_resource(github_token):
	"""Create PyGithub client as a resource with proper cleanup.

	Returns authenticated client if token is available, otherwise anonymous client.
	"""
	logger.info("Initializing GitHub client")

	# Debug: Log token status
	if github_token:
		token_preview = f"{github_token[:8]}..." if len(github_token) > 8 else "***"
		logger.info(f"GitHub token found: {token_preview} (length: {len(github_token)})")
		logger.debug("Creating authenticated GitHub client")
		auth = Auth.Token(github_token)
		client = Github(auth=auth)
	else:
		logger.warning("No GitHub token configured - using anonymous client (rate limit: 60/hour)")
		client = Github()

	# Debug: Log rate limit info
	try:
		rate_limit = client.get_rate_limit()
		core = getattr(rate_limit, 'core', None)
		if core:
			logger.info(f"GitHub rate limit - remaining: {core.remaining}/{core.limit}, resets at: {core.reset}")
		else:
			logger.info(f"GitHub rate limit info: {rate_limit}")
	except Exception as e:
		logger.warning(f"Failed to get rate limit info: {e}")

	try:
		yield client
	finally:
		logger.debug("Closing GitHub client")
		# PyGithub's close() method properly closes the underlying HTTP connection
		client.close()


class Container(containers.DeclarativeContainer):
	config = providers.Configuration(pydantic_settings=[AppConfig()])

	cache = providers.Resource(
		cache_resource,
		cache_dir=config.cache_dir,
		github_cache_ttl_days=config.github_cache_ttl_days,
	)

	# GitHub client with authentication and proper cleanup
	github_client = providers.Resource(
		github_client_resource,
		github_token=config.github_token,
	)

	# Basic HTTP client for non-GitHub APIs (e.g., OSV)
	http_client = providers.Factory(HttpClient)

	index = providers.Factory(OSVAdapter, cache=cache, http_client=http_client)

	enrichers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
		providers.Factory(
			GitHubRepoEnricher,
			cache=cache,
			github_client=github_client,
			github_cache_ttl_days=config.github_cache_ttl_days,
			osv_cache_ttl_days=config.osv_cache_ttl_days,
		),
	)

	dump_providers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
	)

	composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

	list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
	list_iter_uc = providers.Factory(ListVulnerabilitiesIterUseCase, index=index, enricher=composite_enricher)
	detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
	dump_uc = providers.Factory(RawDumpUseCase, providers=dump_providers)
	clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)


