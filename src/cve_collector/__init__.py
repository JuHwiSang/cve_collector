"""cve_collector package: app/core/infra/shared.

Expose library-friendly API client at the package level.
"""

from .app.api import AppConfig, CveCollectorClient

import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__all__ = [
    "CveCollectorClient",
    "AppConfig",
]

