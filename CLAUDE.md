# CLAUDE.md - AI Assistant Context for cve-collector

This document provides comprehensive context for AI assistants working on the cve-collector project.

## Project Overview

**cve-collector** is a Python CLI tool and library for collecting and enriching GitHub Security Advisory (GHSA) vulnerability data from multiple sources (OSV, GitHub).

- **Current Version**: v0.5.2 (Alpha) - Under active development, unstable
- **Architecture**: Clean layered architecture (app/core/infra/shared/config) with dependency injection
- **Language**: Python 3.13+
- **Key Dependencies**: PyGithub, httpx, diskcache, pydantic, dependency-injector, typer

## Architecture Layers

```
src/cve_collector/
  __init__.py               # Package exports (CveCollectorClient, AppConfig)
  app/
    api.py                  # Public library API (CveCollectorClient class)
    cli.py                  # Typer-based CLI entry point
    container.py            # DI container (dependency-injector with Pydantic settings)
  core/
    domain/
      models.py             # Immutable domain models (Vulnerability, Repository, Commit)
      enums.py              # Enums (Severity, ReferenceType)
    ports/
      index_port.py         # Index port (list/get vulnerabilities)
      enrich_port.py        # Enrichment port (add metadata)
      dump_port.py          # Raw JSON dump port
      cache_port.py         # Cache port (get/set/clear)
      clock_port.py         # Clock port (for testing)
    services/
      composite_enricher.py # Composite pattern for multiple enrichers
    usecases/
      list_vulnerabilities.py
      detail_vulnerability.py
      raw_dump.py
      clear_cache.py
  infra/
    osv_adapter.py          # OSV API adapter (IndexPort + EnrichmentPort)
    github_enrichment.py    # GitHub API enricher (PyGithub-based, accepts individual TTL params)
    cache_diskcache.py      # Disk cache implementation (diskcache)
    http_client.py          # HTTP client (httpx, for OSV API)
  shared/
    logging.py              # Logging utilities
    filter_utils.py         # Expression-based filtering (asteval)
    utils.py                # Utility functions (URL parsing, size formatting, PoC detection)
  config/
    settings.py             # Pydantic BaseSettings configuration (AppConfig)
    urls.py                 # API URL builders
    tokens.py               # Token hashing utilities
```

## Key Design Principles

### 1. Immutability
- All domain models use `@dataclass(frozen=True)`
- Updates via `dataclasses.replace()`
- No in-place mutations

### 2. Port-Based Architecture
- Ports defined as `Protocol` (structural typing)
- No inheritance-based abstractions
- Easy to mock/test

### 3. Fail-Fast Error Handling
- No silent fallbacks or default values
- Explicit error propagation
- Errors logged at source

### 4. Type Safety
- No `Any`, `cast`, `getattr`, `type: ignore` in normal flow
- Full type hints everywhere
- Pydantic for runtime validation where needed

### 5. Lazy Enrichment
- Only enrich data when necessary (filtering/limiting)
- Skeleton objects for list operations
- Full enrichment for detail operations

### 6. Smart Caching
- Per-source TTL (OSV: 7 days, GitHub: 30 days)
- Negative caching for 404/403 errors (1 day TTL, error marker: `{"__error__": True}`)
- Prefix-based cache clearing (`osv:`, `gh_repo:`)
- **Rate limiting is NOT cached** - PyGithub handles rate limiting automatically

## Data Flow

### List Vulnerabilities
```
CLI/API
  → ListVulnerabilitiesUseCase
    → OSVAdapter.list_ids(ecosystem) [Index]
      → HTTP call to OSV API (cached 7 days)
    → Two execution paths:

      Fast path (no filter, no enrichment):
        → Apply limit+skip to index results
        → Slice results [skip:]
        → Return skeleton objects

      Lazy path (with filter or enrichment):
        → Fetch all skeleton items from index
        → For each item:
          → Apply enrichment if detailed=True
          → Apply filter if filter_expr provided
          → If item passes filter, increment skip counter
          → Once skip counter reaches skip value, add to results
          → Stop when result count reaches limit
        → Return filtered/enriched/skipped results
```

### Detail Vulnerability
```
CLI/API
  → DetailVulnerabilityUseCase
    → OSVAdapter.get_by_id(ghsa_id or cve_id)
      → HTTP call to OSV API (cached 7 days)
    → CompositeEnricher.enrich(v)
      → OSVAdapter.enrich(v)
      → GitHubRepoEnricher.enrich(v)
    → return fully enriched Vulnerability
```

## Core Domain Models

### Vulnerability
```python
@dataclass(frozen=True)
class Vulnerability:
    ghsa_id: str
    cve_id: str | None = None
    severity: str | None = None
    summary: str | None = None
    description: str | None = None
    details: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    repositories: tuple[Repository, ...] = ()
    commits: tuple[Commit, ...] = ()
    poc_urls: tuple[str, ...] = ()
```

### Repository
```python
@dataclass(frozen=True)
class Repository:
    ecosystem: str
    slug: str  # "owner/name"
    star_count: int | None = None
    size_bytes: int | None = None

    @staticmethod
    def from_github(owner: str, name: str, ecosystem: str = "GitHub") -> Repository:
        return Repository(ecosystem=ecosystem, slug=f"{owner}/{name}")
```

### Commit
```python
@dataclass(frozen=True)
class Commit:
    sha: str
    url: str
```

## Infrastructure Details

### OSVAdapter
- **Role**: Primary index + basic enrichment (GHSA/CVE data from OSV)
- **Implements**: `IndexPort`, `VulnerabilityEnrichmentPort`, `DumpProviderPort`
- **API**: `https://api.osv.dev/v1/vulns/{GHSA-ID}` or `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`
- **Cache**: `osv:{GHSA-ID}` (7 days TTL)
- **Error handling**: 404 → None, other errors → exception

### GitHubRepoEnricher
- **Role**: Enrich with GitHub repository metadata (stars, size)
- **Implements**: `VulnerabilityEnrichmentPort`
- **Library**: PyGithub (not httpx)
- **Authentication**: `Auth.Token(github_token)` if available, else anonymous
- **Cache**: `gh_repo:{owner}/{name}` (30 days TTL)
- **Negative caching**: 404/403 → `{"__error__": True}` (1 day TTL)
- **Rate limiting**: PyGithub automatically raises `RateLimitExceededException`
  - Authenticated: 5000 req/hour
  - Anonymous: 60 req/hour
- **Size conversion**: GitHub API returns KB, we convert to bytes (`size * 1024`)

### DiskCacheAdapter
- **Library**: `diskcache.Cache`
- **Location**: `platformdirs.user_cache_dir("cve-collector") / namespace`
- **Operations**:
  - `get(key) -> bytes | None`
  - `set(key, value, ttl_seconds)`
  - `clear(prefix)` - prefix-based deletion
  - `iter_keys(prefix)` - iterate keys with prefix
- **JSON helpers**: `get_json`, `set_json`, `get_model`, `set_model` (in `CachePort` base)
- **Context manager**: Supports `with` statement

### HttpClient
- **Library**: `httpx.Client`
- **Features**:
  - Session reuse
  - Timeout: 20s default
  - Redirect following (max 10)
  - JSON response validation (must be object)
- **Usage**: OSV API only (GitHub uses PyGithub)
- **No rate limiting** - rate limiter was removed, PyGithub handles it for GitHub API

## CLI Commands

### list
```bash
cve-collector list [OPTIONS]

Options:
  --ecosystem TEXT       Filter by ecosystem (npm, pypi, go, etc.)
  --limit INTEGER        Limit results (default: 10)
  --skip INTEGER         Skip first N results (default: 0)
  -d, --detail          Show detailed view (severity, ecosystem, repo, stars, size)
  -f, --filter TEXT     Filter expression (e.g., 'stars > 1000')
```

### detail
```bash
cve-collector detail <ID>

Arguments:
  ID  GHSA or CVE identifier (e.g., GHSA-xxxx-xxxx-xxxx or CVE-2024-12345)
```

### dump
```bash
cve-collector dump <ID>

Arguments:
  ID  GHSA identifier - returns raw JSON from all providers
```

### clear
```bash
cve-collector clear [PREFIX]

Arguments:
  PREFIX  Optional cache prefix (osv, gh_repo) - clears all if omitted
```

### ingest
```bash
cve-collector ingest <ECOSYSTEM>...

Arguments:
  ECOSYSTEM  One or more ecosystem names to ingest (e.g., npm, pypi, go)

Options:
  --force    Re-download and re-index even if cache exists
```

## Library API

### CveCollectorClient Class

The library API is now class-based instead of function-based. This provides better resource management and allows configuration to be set once per client instance.

**Location**: `src/cve_collector/app/api.py`

**Exports**: `src/cve_collector/__init__.py` exports `CveCollectorClient` and `AppConfig`

### Constructor

```python
class CveCollectorClient:
    def __init__(
        self,
        *,
        github_token: str | None = None,
        cache_dir: str | Path | None = None,
        github_cache_ttl_days: int | None = None,
        osv_cache_ttl_days: int | None = None,
    ):
        """Initialize the CVE Collector client.

        Args:
            github_token: Optional GitHub token. If None, uses environment variable.
            cache_dir: Optional custom cache directory.
            github_cache_ttl_days: Optional TTL for GitHub cache (days).
            osv_cache_ttl_days: Optional TTL for OSV cache (days).

        All parameters are optional. Unspecified values fall back to environment variables
        or default values from AppConfig.
        """
```

### Usage Pattern

```python
from cve_collector import CveCollectorClient

# Basic usage with context manager (recommended)
with CveCollectorClient() as client:
    vulns = client.list_vulnerabilities(ecosystem="npm", limit=10)
    detail = client.detail("GHSA-xxxx-xxxx-xxxx")

# With custom settings
with CveCollectorClient(github_token="ghp_xxx", cache_dir="/tmp/cache") as client:
    vulns = client.list_vulnerabilities(ecosystem="npm", detailed=True)

# Without context manager (must call close())
client = CveCollectorClient(github_token="ghp_xxx")
try:
    vulns = client.list_vulnerabilities(ecosystem="npm")
finally:
    client.close()
```

### Methods

#### list_vulnerabilities()
```python
def list_vulnerabilities(
    self,
    *,
    ecosystem: str | None = None,
    limit: int | None = None,
    skip: int = 0,
    detailed: bool = False,
    filter_expr: str | None = None,
) -> Sequence[Vulnerability]:
    """Return a list of vulnerabilities.

    Args:
        ecosystem: Ecosystem name (e.g., npm). If None, lists all ecosystems.
        limit: Maximum number of results. If None, returns all results.
        skip: Number of results to skip (default: 0). Useful for pagination.
        detailed: If True, enriches items with GitHub metadata (stars, size).
        filter_expr: Filter expression (e.g., 'stars > 1000', 'severity == "HIGH"').

    Returns:
        List of Vulnerability objects.

    Raises:
        ValueError: If filter_expr is invalid.
    """
```

#### detail()
```python
def detail(self, id: str) -> Vulnerability | None:
    """Return a single detailed vulnerability by ID (GHSA-... or CVE-...)."""
```

#### dump()
```python
def dump(self, id: str) -> list[dict]:
    """Return raw JSON payloads for the ID across configured providers."""
```

#### clear_cache()
```python
def clear_cache(self, prefix: str | None = None) -> None:
    """Clear caches. Without prefix, clears all. With prefix, clears only matching keys."""
```

#### ingest()
```python
def ingest(self, ecosystems: Sequence[str], *, force: bool = False) -> dict[str, int]:
    """Ingest vulnerability data for specified ecosystems.

    Args:
        ecosystems: List of ecosystem names (e.g., ['npm', 'pypi', 'go']).
        force: If True, re-download and re-index even if cache exists.

    Returns:
        Dictionary mapping ecosystem names to number of entries ingested.
        Example: {'npm': 1234, 'pypi': 567}
    """
```

#### close()
```python
def close(self) -> None:
    """Close the client and release resources.

    This method is automatically called when using context manager (with statement).
    """
```

## Filter Expression System

### Available Variables
- `ghsa_id` (str)
- `cve_id` (str | None)
- `has_cve` (bool)
- `severity` (str | None) - "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"
- `summary` (str | None)
- `description` (str | None)
- `details` (str | None)
- `published_at` (datetime | None)
- `modified_at` (datetime | None)
- `ecosystem` (str | None) - first repository's ecosystem
- `repo_slug` (str | None) - first repository's slug
- `stars` (int | None) - first repository's star count
- `size_bytes` (int | None) - first repository's size
- `repo_count` (int)
- `commit_count` (int)
- `poc_count` (int)

### Example Expressions
```python
'stars > 1000'
'severity == "HIGH"'
'severity in ["CRITICAL", "HIGH"]'
'has_cve and stars > 500'
'ecosystem == "npm" and severity != "LOW"'
'poc_count > 0'
```

### Implementation
- Uses `asteval` library (safe eval)
- Expression compiled once per filter
- Applied after enrichment (to have all metadata available)

## Configuration

### Pydantic BaseSettings Configuration

Configuration is managed via Pydantic `BaseSettings` for automatic environment variable loading and validation.

**Location**: `src/cve_collector/config/settings.py`

### Environment Variables

All settings use the `CVE_COLLECTOR_` prefix:

```bash
CVE_COLLECTOR_GITHUB_TOKEN=ghp_...        # GitHub token for authenticated API access
CVE_COLLECTOR_CACHE_DIR=/path/to/cache    # Custom cache directory (optional)
CVE_COLLECTOR_GITHUB_CACHE_TTL_DAYS=30    # GitHub repo metadata cache TTL (default: 30)
CVE_COLLECTOR_OSV_CACHE_TTL_DAYS=7        # OSV vulnerability data cache TTL (default: 7)
```

### .env File Support
- CLI automatically loads `.env` from working directory using `python-dotenv`
- Loaded in `cli.py:main()` before container initialization
- Pydantic BaseSettings also supports `.env` file loading automatically

### AppConfig (Pydantic BaseSettings)

```python
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CVE_COLLECTOR_",
        case_sensitive=False,
        extra="forbid",
    )

    github_token: Optional[str] = Field(
        default=None,
        description="GitHub personal access token"
    )

    cache_dir: Optional[Path] = Field(
        default=None,
        description="Custom cache directory path"
    )

    github_cache_ttl_days: int = Field(
        default=30,
        ge=1,
        description="TTL for GitHub repo metadata cache (days)"
    )

    osv_cache_ttl_days: int = Field(
        default=7,
        ge=1,
        description="TTL for OSV vulnerability data cache (days)"
    )
```

### Usage

**CLI**: Configuration is automatically loaded from environment variables and `.env` file.

**Library**: Can override settings per-client instance:

```python
from cve_collector import CveCollectorClient

# Use defaults (from environment)
with CveCollectorClient() as client:
    vulns = client.list_vulnerabilities(ecosystem="npm")

# Override specific settings
with CveCollectorClient(
    github_token="ghp_xxx",
    cache_dir="/tmp/cache",
    github_cache_ttl_days=60
) as client:
    vulns = client.list_vulnerabilities(ecosystem="npm")
```

## Dependency Injection

### Container Structure with Pydantic Configuration

The container uses `providers.Configuration(pydantic_settings=[AppConfig()])` to integrate Pydantic BaseSettings with dependency-injector. This allows automatic environment variable loading and clean dependency injection.

```python
class Container(containers.DeclarativeContainer):
    # Pydantic configuration integration
    config = providers.Configuration(pydantic_settings=[AppConfig()])

    # Resources receive individual config values (not the whole AppConfig object)
    cache = providers.Resource(
        cache_resource,
        cache_dir=config.cache_dir,
        github_cache_ttl_days=config.github_cache_ttl_days,
    )

    github_client = providers.Resource(
        github_client_resource,
        github_token=config.github_token,
    )

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
    detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
    dump_uc = providers.Factory(RawDumpUseCase, providers=dump_providers)
    clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)
```

### Key Points

1. **Pydantic Integration**: `providers.Configuration(pydantic_settings=[AppConfig()])` loads settings from environment variables automatically
2. **Individual Parameters**: Resources/factories receive specific config values (e.g., `github_token`) rather than entire config objects
3. **Clean Dependencies**: Each component only knows about the settings it needs
4. **Override Support**: `container.config.from_pydantic(custom_config)` allows runtime configuration override

### Resource Management
- `cache`: Context manager, auto-closes
- `github_client`: PyGithub client, auto-closes via `client.close()`
- Resources initialized lazily
- Proper cleanup on exit

## Testing Strategy

### Test Structure
```
tests/
  cve_collector/
    core/           # Unit tests (domain, usecases)
    infra/          # Integration tests (adapters, cache)
    app/            # E2E tests (CLI)
```

### Testing Principles
- Mock external APIs (OSV, GitHub)
- Use real cache (tempfile.TemporaryDirectory)
- Test error cases explicitly
- Verify caching behavior
- No network calls in tests

### Key Test Cases
- **OSVAdapter**: HTTP responses, caching, error handling
- **GitHubRepoEnricher**: Enrichment, negative caching, rate limit handling
- **DiskCacheAdapter**: TTL, prefix clearing, JSON serialization
- **Filter**: Expression evaluation, type coercion, edge cases
- **Skip parameter**: Fast path skip, lazy path skip, skip with filter/enrichment/limit combinations

## Common Pitfalls & Gotchas

### 1. Cache Keys Must Be Namespaced
```python
# CORRECT
cache.set("osv:GHSA-1234", data)
cache.set("gh_repo:owner/name", data)

# WRONG - no namespace
cache.set("GHSA-1234", data)
```

### 2. GitHub API Size is in KB
```python
# CORRECT
size_bytes = repo.size * 1024

# WRONG - assuming bytes
size_bytes = repo.size
```

### 3. Enrichment Order Matters
```python
# CORRECT - OSV first (provides basic data), then GitHub (adds metadata)
enrichers = [osv_adapter, github_enricher]

# WRONG - GitHub first won't have repository data to enrich
enrichers = [github_enricher, osv_adapter]
```

### 4. Rate Limit Errors Should Not Be Cached
```python
# CORRECT
except RateLimitExceededException:
    raise  # Don't cache, re-raise immediately

# WRONG
except RateLimitExceededException:
    cache.set(key, {"__error__": True})  # DON'T cache rate limits
```

### 5. Filter Expressions Run After Enrichment
```python
# This means filtering by 'stars' requires detailed=True
# Otherwise stars will be None and filter won't work as expected
list_vulnerabilities(ecosystem="npm", detailed=True, filter_expr='stars > 1000')
```

### 6. PyGithub Uses .raw_data for Full Repo Info
```python
# CORRECT
repo = github_client.get_repo(f"{owner}/{name}")
return repo.raw_data  # Dict with all fields

# WRONG - only gets specific fields
return {"stars": repo.stargazers_count, "size": repo.size}
```

### 7. Utility Functions Should Be Pure
```python
# CORRECT - pure utility, caller handles None
from shared.utils import format_size
size_str = format_size(size_bytes) if size_bytes is not None else "-"

# WRONG - utility handling business logic
def format_size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "-"  # Presentation logic in utility
    ...
```

## Development Workflow

### Adding a New Enricher
1. Create enricher in `infra/` implementing `VulnerabilityEnrichmentPort`
2. Add to `container.py` enrichers list
3. Update cache prefix in README/docs
4. Add tests in `tests/infra/`

### Adding a New Filter Variable
1. Add property to `filter_utils.py:_create_filter_context()`
2. Update README and docs with new variable
3. Add test cases

### Adding a New CLI Command
1. Add command function in `cli.py` with `@app.command()`
2. Create/update usecase in `core/usecases/`
3. Wire usecase in `container.py`
4. Add corresponding function to `api.py` for library users
5. Update CLAUDE.md with both CLI and API usage
6. Add to README

### Adding Utility Functions
1. Add pure utility functions to `shared/utils.py`
2. Keep utilities focused on single responsibility (no None/business logic handling)
3. Add comprehensive docstrings with examples
4. Presentation logic (None handling, formatting) stays in caller (e.g., `cli.py`)
5. Add tests in `tests/shared/`

### Modifying Domain Models
1. Update model in `core/domain/models.py`
2. Update all adapters that create/transform the model
3. Update filter context if adding filterable fields
4. Run tests to find breakages
5. Update docs

## Debugging Tips

### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Cache Contents
```python
from cve_collector.infra.cache_diskcache import DiskCacheAdapter

with DiskCacheAdapter(namespace="github") as cache:
    for key in cache.iter_keys("osv:"):
        print(key, cache.get_json(key))
```

### Test GitHub Token
```python
from github import Github, Auth

auth = Auth.Token("ghp_...")
client = Github(auth=auth)
rate = client.get_rate_limit()
print(f"Remaining: {rate.core.remaining}/{rate.core.limit}")
```

### Bypass Cache for Testing
```bash
# Clear cache before running
cve-collector clear

# Or use custom cache dir
export CVE_COLLECTOR_CACHE_DIR=/tmp/test-cache
```

## Known Issues & Limitations

### Current Limitations
1. **No async support** - all operations are synchronous
2. **Single-threaded enrichment** - no parallel API calls
3. **No retry logic** - HTTP errors fail immediately (except httpx built-in)
4. **Limited OSV ecosystem support** - depends on OSV data availability
5. **Skip-based pagination only** - no cursor or page-based pagination (skip/limit only)
6. **GitHub API rate limit shared** - multiple processes with same token share limit via PyGithub

### Future Improvements
- Async/await for concurrent enrichment
- Configurable retry with exponential backoff
- Cursor-based pagination for better performance with large datasets
- More enrichment sources (NVD, etc.)
- Advanced filtering (regex, date ranges)
- Export formats (JSON, CSV, SARIF)

## Breaking Changes History

### v0.5.3 (Current - 2025-10-30)
- **BREAKING: Class-based API**: Complete refactor from function-based to class-based API
  - Old: `from cve_collector import list_vulnerabilities, detail, dump, clear_cache`
  - New: `from cve_collector import CveCollectorClient`
  - Migration: Wrap function calls in `with CveCollectorClient() as client:` context manager
- **Configuration system overhaul**: Pydantic BaseSettings integration
  - Environment variables now use `CVE_COLLECTOR_` prefix (was `GITHUB_TOKEN`, now `CVE_COLLECTOR_GITHUB_TOKEN`)
  - Configuration in `config/settings.py` (was `config/types.py` + `config/loader.py`)
  - Container uses `providers.Configuration(pydantic_settings=[AppConfig()])` for automatic env loading
- **File structure changes**:
  - Moved `api.py` from `src/` to `app/api.py`
  - Renamed `config/token_utils.py` to `config/tokens.py`
  - Deleted `config/constants.py`, `config/types.py`, `config/loader.py`
- **Dependency injection improvements**:
  - Resources/factories receive individual config values instead of entire AppConfig object
  - `GitHubRepoEnricher.__init__` signature changed: accepts `github_cache_ttl_days` and `osv_cache_ttl_days` instead of `app_config`
- **CveCollectorClient constructor**: Accepts individual parameters (pythonic)
  - `github_token`, `cache_dir`, `github_cache_ttl_days`, `osv_cache_ttl_days`
  - All parameters optional, falls back to environment variables
  - Example: `CveCollectorClient(github_token="ghp_xxx", cache_dir="/tmp")`
- **NEW: Skip parameter for pagination**: Added `skip` parameter to list operations
  - CLI: `cve-collector list --skip N` to skip first N results
  - API: `client.list_vulnerabilities(skip=N)` (default: 0)
  - UseCase: `ListVulnerabilitiesUseCase.execute(skip=N)`
  - Works in both fast path (no filter/enrichment) and lazy path (with filter/enrichment)
  - Skip is applied after filtering, so `skip=10` skips 10 filtered results, not 10 raw results

### v0.5.2
- **API parity with CLI**: Added missing parameters to library API
  - `list_vulnerabilities()`: Added `filter_expr` parameter, made `ecosystem` optional (can be `None` to list all)
  - Added `ingest()` function to library API
- **Refactored utilities**: Moved `format_size()` to `shared/utils.py`
  - Changed signature to accept only `int` (not `int | None`)
  - None handling moved to callers (separation of concerns)
- All CLI commands now have equivalent library API functions

### v0.5.0
- Removed custom rate limiter (now using PyGithub's built-in)
- Removed `rate_limiter.py`, `rate_limiter_port.py`
- Updated cache structure (removed `rate_limit:` prefix)

### v0.4.0
- Switched from custom GitHub API to PyGithub
- Changed authentication to `Auth.Token` pattern
- Updated resource management in container

### v0.3.0
- Introduced filter expression system
- Added `filter_utils.py`
- Breaking: changed list API signature

## Related Documentation

- [README.md](README.md) - User-facing documentation
- [docs/cve_collector2.md](docs/cve_collector2.md) - Detailed architecture documentation (Korean)
- [pyproject.toml](pyproject.toml) - Project metadata and dependencies

## Quick Reference Commands

```bash
# Install for development
pip install -e ".[tests]"

# Run all tests
pytest

# Run with coverage
pytest --cov=cve_collector --cov-report=html

# Type check
mypy src/

# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Clear cache
cve-collector clear

# Check version
python -c "import cve_collector; print(cve_collector.__version__)"
```

## Contact & Contributing

This project is in early alpha. Contributions are welcome but expect breaking changes.

When contributing:
1. Follow existing code style (immutable models, port-based design)
2. Add tests for new features
3. Update documentation (README, CLAUDE.md, docs/)
4. Use conventional commit messages
5. Open an issue before major changes

---

**Last Updated**: 2025-10-30
**Document Version**: 1.3.0
**Project Version**: v0.5.3 (unreleased)
