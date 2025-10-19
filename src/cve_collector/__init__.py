"""cve_collector package: app/core/infra/shared.

Expose library-friendly API functions at the package level.
"""

from .api import clear_cache, detail, dump, list_vulnerabilities

import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__all__ = [
    "list_vulnerabilities",
    "detail",
    "dump",
    "clear_cache",
]

