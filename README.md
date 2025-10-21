# CVE Collector

> **⚠️ WARNING: This project is under active development and highly unstable.**
> **APIs, CLI commands, and data structures may change without notice.**
> **Not recommended for production use.**

A layered architecture tool for collecting and enriching GitHub Security Advisory (GHSA) vulnerability data from OSV and GitHub APIs.

## Features

- **Multi-source aggregation**: Fetches GHSA data from OSV, enriches with GitHub repository metadata
- **Flexible filtering**: Dynamic expression-based filtering with `asteval` (stars, severity, ecosystem, etc.)
- **Smart caching**: Disk-based cache with configurable TTL and prefix-based clearing
- **Dual interface**: CLI tool and Python library API

## Installation

```bash
# From GitHub
pip install git+https://github.com/JuHwiSang/cve_collector
```

## Configuration

Set your GitHub token as an environment variable:

```bash
# bash/zsh
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN

# PowerShell (persist for future sessions)
setx GITHUB_TOKEN "YOUR_GITHUB_TOKEN"

# PowerShell (current session only)
$env:GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
```

Or create a `.env` file in the working directory:

```bash
GITHUB_TOKEN=YOUR_GITHUB_TOKEN
```

## CLI Usage

### List vulnerabilities

```bash
# List recent vulnerabilities (default: limit=10, all ecosystems from cache)
cve-collector list

# List with specific ecosystem (auto-downloads OSV data if needed)
cve-collector list --ecosystem npm --limit 50

# Detailed view with severity, ecosystem, repository metadata
cve-collector list -d
cve-collector list --ecosystem pypi --detail

# Filter by expression (uses enriched data)
cve-collector list -f 'stars > 1000'
cve-collector list -f 'severity == "HIGH" and has_cve'
cve-collector list -f 'severity in ["CRITICAL", "HIGH"]'
cve-collector list -f 'poc_count > 0'

# Combine options
cve-collector list --ecosystem npm -d -f 'stars > 500' --limit 20
```

### Get vulnerability details

```bash
# By GHSA identifier
cve-collector detail GHSA-2234-fmw7-43wr

# By CVE identifier
cve-collector detail CVE-2024-12345
```

### Dump raw JSON

```bash
# Get original JSON payloads from all providers (OSV, etc.)
cve-collector dump GHSA-2234-fmw7-43wr
```

### Clear cache

```bash
# Clear all cached data
cve-collector clear

# Clear only OSV data (GHSA entries)
cve-collector clear osv

# Clear only GitHub repository metadata (stars, size)
cve-collector clear gh_repo
```

## Python Library API

```python
from cve_collector import list_vulnerabilities, detail, dump, clear_cache

# List vulnerabilities (returns domain objects)
items = list_vulnerabilities(ecosystem="npm", limit=50, detailed=True)

# Filter with expressions
filtered = list_vulnerabilities(
    ecosystem="pypi",
    detailed=True,
    filter_expr='severity == "HIGH" and stars > 1000',
    limit=20
)

# Get single vulnerability detail (by GHSA or CVE ID)
vuln = detail("GHSA-2234-fmw7-43wr")
if vuln:
    print(f"{vuln.ghsa_id}: {vuln.summary}")
    print(f"Severity: {vuln.severity}")
    for repo in vuln.repositories:
        print(f"  Repo: {repo.slug} ({repo.star_count} stars)")

# Get raw JSON from all providers
payloads = dump("GHSA-2234-fmw7-43wr")
for payload in payloads:
    print(payload)

# Clear cache
clear_cache()           # All cache
clear_cache("osv")      # OSV data only
clear_cache("gh_repo")  # GitHub repo metadata only
```

## Filter Expression Syntax

Available variables in filter expressions:

| Variable | Type | Description |
|----------|------|-------------|
| `ghsa_id` | str | GHSA identifier |
| `cve_id` | str \| None | CVE identifier |
| `has_cve` | bool | Whether CVE ID exists |
| `severity` | str \| None | Severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN) |
| `summary` | str \| None | Summary text |
| `description` | str \| None | Description text |
| `details` | str \| None | Detailed description |
| `published_at` | datetime \| None | Publication timestamp |
| `modified_at` | datetime \| None | Last modified timestamp |
| `ecosystem` | str \| None | First repository's ecosystem |
| `repo_slug` | str \| None | First repository's slug (owner/name) |
| `stars` | int \| None | First repository's star count |
| `size_bytes` | int \| None | First repository's size in bytes |
| `repo_count` | int | Number of repositories |
| `commit_count` | int | Number of commits |
| `poc_count` | int | Number of PoC URLs |

Examples:

```bash
# Severity
cve-collector list -f 'severity == "HIGH"'
cve-collector list -f 'severity in ["CRITICAL", "HIGH"]'

# Repository metrics
cve-collector list -f 'stars > 1000'
cve-collector list -f 'size_bytes > 1048576'  # > 1MB

# Complex conditions
cve-collector list -f 'has_cve and stars > 500'
cve-collector list -f 'ecosystem == "npm" and severity != "LOW"'

# Date comparisons
cve-collector list -f 'modified_at > published_at'

# PoC existence
cve-collector list -f 'poc_count > 0'
```

## Cache Structure

Cache keys follow a namespaced pattern:

- `osv:{ID}` - OSV vulnerability data
- `gh_repo:{owner}/{name}` - GitHub repository metadata (stars, size)

## Rate Limiting

GitHub API rate limiting is handled automatically by PyGithub:
- Authenticated users: 5000 requests/hour
- Anonymous users: 60 requests/hour
- PyGithub automatically tracks and raises `RateLimitExceededException` when limit is reached

## Development Status

**Current Version**: v0.5.0 (Alpha)

This project is in early alpha stage. Expect:
- Breaking changes in minor/patch versions
- Incomplete error handling
- Missing features
- Potential data inconsistencies
- Bugs and stability issues

Use at your own risk for experimental/research purposes only.

### Development Setup

```bash
# Install with test dependencies
pip install -e ".[tests]"

# Run tests
pytest

# Run specific test layer
pytest tests/core      # Unit tests
pytest tests/infra     # Integration tests
pytest tests/app       # E2E tests
```
