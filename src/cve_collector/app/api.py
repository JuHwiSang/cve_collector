from __future__ import annotations

from pathlib import Path
from typing import Iterator, Sequence

from .container import Container
from ..config.settings import AppConfig
from ..core.domain.models import Vulnerability


class CveCollectorClient:
    """Client for interacting with CVE vulnerability data.

    This class provides a stateful API for querying and managing vulnerability data.
    The container and its resources are initialized once and reused across multiple calls.

    Example:
        # Using default configuration (from environment variables)
        client = CveCollectorClient()
        vulns = client.list_vulnerabilities(ecosystem="npm", limit=10)
        detail = client.detail("GHSA-xxxx-xxxx-xxxx")
        client.close()

        # Using context manager (recommended)
        with CveCollectorClient() as client:
            vulns = client.list_vulnerabilities(ecosystem="npm", detailed=True)

        # Customize settings
        with CveCollectorClient(github_token="ghp_xxx", cache_dir="/custom/cache") as client:
            vulns = client.list_vulnerabilities(ecosystem="npm")

        # Only override token
        with CveCollectorClient(github_token="ghp_xxx") as client:
            vulns = client.list_vulnerabilities(ecosystem="npm", detailed=True)
    """

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
            github_token: Optional GitHub personal access token for API authentication.
                         If None, uses CVE_COLLECTOR_GITHUB_TOKEN environment variable.
            cache_dir: Optional custom cache directory path.
                      If None, uses CVE_COLLECTOR_CACHE_DIR or default user cache directory.
            github_cache_ttl_days: Optional TTL for GitHub repository metadata cache (in days).
                                  If None, uses CVE_COLLECTOR_GITHUB_CACHE_TTL_DAYS or default (30).
            osv_cache_ttl_days: Optional TTL for OSV vulnerability data cache (in days).
                               If None, uses CVE_COLLECTOR_OSV_CACHE_TTL_DAYS or default (7).

        Example:
            # Use all defaults (from environment)
            client = CveCollectorClient()

            # Override only token
            client = CveCollectorClient(github_token="ghp_xxx")

            # Override multiple settings
            client = CveCollectorClient(
                github_token="ghp_xxx",
                cache_dir="/tmp/my-cache",
                github_cache_ttl_days=60
            )
        """
        self._container = Container()

        # Build config dict with only provided values
        config_dict = {}
        if github_token is not None:
            config_dict["github_token"] = github_token
        if cache_dir is not None:
            config_dict["cache_dir"] = Path(cache_dir) if isinstance(cache_dir, str) else cache_dir
        if github_cache_ttl_days is not None:
            config_dict["github_cache_ttl_days"] = github_cache_ttl_days
        if osv_cache_ttl_days is not None:
            config_dict["osv_cache_ttl_days"] = osv_cache_ttl_days

        # Override config if any settings provided
        if config_dict:
            config = AppConfig(**config_dict)
            self._container.config.from_pydantic(config)

        self._container.init_resources()

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

        When detailed=True, items are enriched via configured enrichers.

        Args:
            ecosystem: Ecosystem name (e.g., npm). If None, lists all ecosystems.
            limit: Maximum number of results to return. If None, returns all results.
            skip: Number of results to skip (default: 0). Useful for pagination.
            detailed: If True, enriches items with additional metadata (GitHub stars, size, etc.).
            filter_expr: Filter expression using Python syntax.
                        Examples: 'stars > 1000', 'severity == "HIGH"', 'has_cve and stars > 500'.
                        Filter variables: ghsa_id, cve_id, has_cve, severity, summary, description, details,
                        published_at, modified_at, ecosystem, repo_slug, stars, size_bytes,
                        repo_count, commit_count, poc_count.

        Returns:
            List of Vulnerability objects.

        Raises:
            ValueError: If filter_expr is invalid or contains syntax errors.

        Example:
            with CveCollectorClient() as client:
                # List npm vulnerabilities
                vulns = client.list_vulnerabilities(ecosystem="npm", limit=10)

                # List with pagination (skip first 10)
                vulns = client.list_vulnerabilities(ecosystem="npm", limit=10, skip=10)

                # List with enrichment and filtering
                vulns = client.list_vulnerabilities(
                    ecosystem="npm",
                    detailed=True,
                    filter_expr='stars > 1000 and severity == "HIGH"'
                )
        """
        uc = self._container.list_uc()
        return uc.execute(ecosystem=ecosystem, limit=limit, skip=skip, detailed=detailed, filter_expr=filter_expr)

    def list_vulnerabilities_iter(
        self,
        *,
        ecosystem: str | None = None,
        limit: int | None = None,
        skip: int = 0,
        detailed: bool = False,
        filter_expr: str | None = None,
    ) -> Iterator[Vulnerability]:
        """Return an iterator of vulnerabilities.

        This method returns an iterator instead of a list, allowing lazy evaluation
        and memory-efficient processing of large result sets.

        Args:
            ecosystem: Ecosystem name (e.g., npm). If None, lists all ecosystems.
            limit: Maximum number of results to return. If None, returns all results.
            skip: Number of results to skip (default: 0). Useful for pagination.
            detailed: If True, enriches items with additional metadata (GitHub stars, size, etc.).
            filter_expr: Filter expression using Python syntax.
                        Examples: 'stars > 1000', 'severity == "HIGH"', 'has_cve and stars > 500'.
                        Filter variables: ghsa_id, cve_id, has_cve, severity, summary, description, details,
                        published_at, modified_at, ecosystem, repo_slug, stars, size_bytes,
                        repo_count, commit_count, poc_count.

        Returns:
            Iterator of Vulnerability objects.

        Raises:
            ValueError: If filter_expr is invalid or contains syntax errors.

        Example:
            with CveCollectorClient() as client:
                # Process vulnerabilities one at a time
                for vuln in client.list_vulnerabilities_iter(ecosystem="npm", detailed=True):
                    print(f"{vuln.ghsa_id}: {vuln.severity}")

                # With filtering
                high_severity = client.list_vulnerabilities_iter(
                    ecosystem="npm",
                    detailed=True,
                    filter_expr='severity == "HIGH"',
                    limit=100
                )
                for vuln in high_severity:
                    process(vuln)
        """
        uc = self._container.list_iter_uc()
        return uc.execute(ecosystem=ecosystem, limit=limit, skip=skip, detailed=detailed, filter_expr=filter_expr)

    def detail(self, id: str) -> Vulnerability | None:
        """Return a single detailed vulnerability by ID.

        Args:
            id: Vulnerability identifier (GHSA-... or CVE-...).

        Returns:
            Vulnerability object if found, None otherwise.

        Example:
            with CveCollectorClient() as client:
                vuln = client.detail("GHSA-xxxx-xxxx-xxxx")
                if vuln:
                    print(f"Severity: {vuln.severity}")
        """
        uc = self._container.detail_uc()
        return uc.execute(id)

    def dump(self, id: str) -> list[dict]:
        """Return raw JSON payloads for the ID across configured providers.

        Args:
            id: Vulnerability identifier (GHSA-... or CVE-...).

        Returns:
            List of raw JSON dictionaries from each configured provider.

        Example:
            with CveCollectorClient() as client:
                payloads = client.dump("GHSA-xxxx-xxxx-xxxx")
                for payload in payloads:
                    print(payload)
        """
        uc = self._container.dump_uc()
        return uc.execute(id)

    def clear_cache(self, prefix: str | None = None) -> None:
        """Clear cache entries.

        Args:
            prefix: Optional cache key prefix to clear (e.g., 'osv', 'gh_repo').
                   If None, clears all cache.

        Example:
            with CveCollectorClient() as client:
                # Clear all cache
                client.clear_cache()

                # Clear only OSV cache
                client.clear_cache("osv")

                # Clear only GitHub repo cache
                client.clear_cache("gh_repo")
        """
        uc = self._container.clear_cache_uc()
        uc.execute(prefix=prefix)

    def ingest(self, ecosystems: Sequence[str], *, force: bool = False) -> dict[str, int]:
        """Ingest vulnerability data for specified ecosystems.

        Args:
            ecosystems: List of ecosystem names to ingest (e.g., ['npm', 'pypi', 'go']).
            force: If True, re-download and re-index even if cache exists. Default is False.

        Returns:
            Dictionary mapping ecosystem names to the number of entries ingested.
            Example: {'npm': 1234, 'pypi': 567}

        Example:
            with CveCollectorClient() as client:
                # Ingest npm and pypi ecosystems
                results = client.ingest(["npm", "pypi"])
                print(f"Ingested: {results}")

                # Force re-ingest
                results = client.ingest(["npm"], force=True)
        """
        index = self._container.index()
        results = {}
        for eco in ecosystems:
            if not force:
                existing = index.list(ecosystem=eco, limit=1)
                if len(existing) > 0:
                    results[eco] = 0  # Skip, already ingested
                    continue
            count = index.ingest_zip(eco)
            results[eco] = count
        return results

    def close(self) -> None:
        """Close the client and release resources.

        This method should be called when the client is no longer needed,
        or use the context manager (with statement) for automatic cleanup.

        Example:
            client = CveCollectorClient()
            try:
                vulns = client.list_vulnerabilities(ecosystem="npm")
            finally:
                client.close()
        """
        self._container.shutdown_resources()

    def __enter__(self) -> CveCollectorClient:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


__all__ = [
    "CveCollectorClient",
    "AppConfig",
]
