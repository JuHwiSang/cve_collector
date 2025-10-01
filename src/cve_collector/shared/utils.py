from __future__ import annotations

import re
from urllib.parse import urlparse
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
    return m.group("owner"), m.group("name")


def is_poc_url(url: str) -> bool:
    lowered = url.lower()
    if any(k in lowered for k in ("poc", "exploit", "demo", "payload", "reproduce", "proof-of-concept")):
        return True
    normalized = re.sub(r"[^a-z0-9]", "", lowered)
    if "proofofconcept" in normalized:
        return True
    return False


