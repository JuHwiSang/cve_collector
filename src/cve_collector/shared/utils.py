from __future__ import annotations

import re
from typing import Optional, Tuple


GITHUB_COMMIT_RE = re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<name>[^/]+)/commit/(?P<commit>[0-9a-fA-F]{6,40})$")
GITHUB_REPO_RE = re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<name>[^/]+)$")


def parse_github_commit_url(url: str) -> Optional[Tuple[str, str, str]]:
    m = GITHUB_COMMIT_RE.match(url)
    if not m:
        return None
    return m.group("owner"), m.group("name"), m.group("commit")


def parse_github_repo_url(url: str) -> Optional[Tuple[str, str]]:
    m = GITHUB_REPO_RE.match(url)
    if not m:
        return None
    owner = m.group("owner")
    # Ignore GitHub advisories pseudo-owner (not a real repository)
    if owner.lower() == "advisories":
        return None
    return owner, m.group("name")


def is_poc_url(url: str) -> bool:
    lowered = url.lower()
    if any(k in lowered for k in ("poc", "exploit", "demo", "payload", "reproduce", "proof-of-concept")):
        return True
    normalized = re.sub(r"[^a-z0-9]", "", lowered)
    if "proofofconcept" in normalized:
        return True
    return False


def format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable string with appropriate unit.

    Args:
        size_bytes: Size in bytes (must be a valid integer).

    Returns:
        Human-readable size string (e.g., "1.5MB", "512KB").

    Examples:
        >>> format_size(512)
        '512B'
        >>> format_size(1536)
        '1.5KB'
        >>> format_size(1572864)
        '1.5MB'
        >>> format_size(1610612736)
        '1.50GB'
    """
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f}GB"


