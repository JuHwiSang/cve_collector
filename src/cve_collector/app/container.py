from __future__ import annotations

import logging

from dependency_injector import containers, providers
from github import Auth, Github

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

logger = logging.getLogger(__name__)


def cache_resource(app_cfg: AppConfig):
	cache_dir = app_cfg.cache_dir
	with DiskCacheAdapter(
		namespace="github",
		default_ttl_seconds=30 * 24 * 3600,
		base_dir=cache_dir,
	) as cache:
		yield cache


def github_client_resource(app_cfg: AppConfig):
	"""Create PyGithub client as a resource with proper cleanup.

	Returns authenticated client if token is available, otherwise anonymous client.
	"""
	# Debug: Log token status
	if app_cfg.github_token:
		token_preview = f"{app_cfg.github_token[:8]}..." if len(app_cfg.github_token) > 8 else "***"
		logger.info(f"GitHub token found: {token_preview} (length: {len(app_cfg.github_token)})")
		auth = Auth.Token(app_cfg.github_token)
		client = Github(auth=auth)
	else:
		logger.warning("No GitHub token configured - using anonymous client")
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
		# PyGithub's close() method properly closes the underlying HTTP connection
		client.close()


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

	# GitHub client with authentication and proper cleanup
	github_client = providers.Resource(github_client_resource, app_config)

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

	# Basic HTTP client for non-GitHub APIs (e.g., OSV)
	http_client = providers.Factory(HttpClient)

	index = providers.Factory(OSVAdapter, cache=cache, http_client=http_client)

	enrichers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
		providers.Factory(GitHubRepoEnricher, cache=cache, github_client=github_client, app_config=app_config),
	)

	dump_providers = providers.List(
		providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
	)

	composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

	list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
	detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
	dump_uc = providers.Factory(RawDumpUseCase, providers=dump_providers)
	clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)


