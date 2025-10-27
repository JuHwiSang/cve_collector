# CLAUDE.md - AI Assistant Context for cve-collector

This document provides comprehensive context for AI assistants working on the cve-collector project.

## Project Overview

**cve-collector** is a Python CLI tool and library for collecting and enriching GitHub Security Advisory (GHSA) vulnerability data from multiple sources (OSV, GitHub).

- **Current Version**: v0.5.0 (Alpha) - Under active development, unstable
- **Architecture**: Clean layered architecture (app/core/infra/shared/config) with dependency injection
- **Language**: Python 3.13+
- **Key Dependencies**: PyGithub, httpx, diskcache, pydantic, dependency-injector, typer

## Architecture Layers

```
src/cve_collector/
  api.py                    # Public library API (list_vulnerabilities, detail, dump, clear_cache)
  app/
    cli.py                  # Typer-based CLI entry point
    container.py            # DI container (dependency-injector)
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
    github_enrichment.py    # GitHub API enricher (PyGithub-based)
    cache_diskcache.py      # Disk cache implementation (diskcache)
    http_client.py          # HTTP client (httpx, for OSV API)
  shared/
    logging.py              # Logging utilities
    filter_utils.py         # Expression-based filtering (asteval)
  config/
    types.py                # Configuration types (AppConfig)
    loader.py               # Environment loader
    urls.py                 # API URL builders
    token_utils.py          # Token hashing utilities
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
    → CompositeEnricher.enrich_many(skeleton_items)
      → OSVAdapter.enrich(v) [basic GHSA data]
      → GitHubRepoEnricher.enrich(v) [stars, size]
    → filter_utils.filter_items(items, expr) [if filter_expr provided]
    → return filtered/limited results
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

### Environment Variables
```bash
GITHUB_TOKEN=ghp_...        # Required for authenticated GitHub API access
CVE_COLLECTOR_CACHE_DIR=... # Optional: custom cache directory
```

### .env File Support
- CLI automatically loads `.env` from working directory
- Uses `python-dotenv`
- Loaded in `cli.py:main()` before container initialization

### AppConfig
```python
@dataclass(frozen=True)
class AppConfig:
    github_token: str | None
    cache_dir: Path | None  # None = use platformdirs default
    github_cache_ttl_days: int = 30
    osv_cache_ttl_days: int = 7
```

## Dependency Injection

### Container Structure
```python
class Container(containers.DeclarativeContainer):
    app_config = providers.Callable(load_config)
    cache = providers.Resource(cache_resource, app_config)
    github_client = providers.Resource(github_client_resource, app_config)
    http_client = providers.Factory(HttpClient)

    index = providers.Factory(OSVAdapter, cache=cache, http_client=http_client)

    enrichers = providers.List(
        providers.Factory(OSVAdapter, cache=cache, http_client=http_client),
        providers.Factory(GitHubRepoEnricher, cache=cache, github_client=github_client, app_config=app_config),
    )

    composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

    list_uc = providers.Factory(ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
    detail_uc = providers.Factory(DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
    dump_uc = providers.Factory(RawDumpUseCase, providers=dump_providers)
    clear_cache_uc = providers.Factory(ClearCacheUseCase, cache=cache)
```

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
4. Add to README

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
5. **No pagination** - list operations load all IDs into memory
6. **GitHub API rate limit shared** - multiple processes with same token share limit via PyGithub

### Future Improvements
- Async/await for concurrent enrichment
- Configurable retry with exponential backoff
- Streaming/pagination for large result sets
- More enrichment sources (NVD, etc.)
- Advanced filtering (regex, date ranges)
- Export formats (JSON, CSV, SARIF)

## Breaking Changes History

### v0.5.0 (Current)
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

**Last Updated**: 2025-10-27
**Document Version**: 1.0.0
**Project Version**: v0.5.0
