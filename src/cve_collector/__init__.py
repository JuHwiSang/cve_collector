"""cve_collector package: app/core/infra/shared.

Expose library-friendly API functions at the package level.
"""

from .api import clear_cache, detail, dump, list_vulnerabilities

__all__ = [
    "list_vulnerabilities",
    "detail",
    "dump",
    "clear_cache",
]

