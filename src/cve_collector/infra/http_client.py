from __future__ import annotations

from typing import Mapping, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from ..core.ports.rate_limiter_port import RateLimiterPort


class HttpClient:
    def __init__(
        self,
        base_headers: Optional[Mapping[str, str]] = None,
        timeout_seconds: float = 20.0,
        rate_limiter: Optional["RateLimiterPort"] = None
    ) -> None:
        self._client = httpx.Client(
            timeout=timeout_seconds,
            headers=dict(base_headers or {}),
            follow_redirects=True,
            max_redirects=10
        )
        self._rate_limiter = rate_limiter

    def get_json(self, url: str) -> dict:
        if self._rate_limiter:
            self._rate_limiter.acquire()
        resp = self._client.get(url)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError("HttpClient invariant violated: expected JSON object")
        return data

    def post_json(self, url: str, payload: dict) -> dict:
        if self._rate_limiter:
            self._rate_limiter.acquire()
        resp = self._client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError("HttpClient invariant violated: expected JSON object")
        return data

    def get_bytes(self, url: str) -> bytes:
        if self._rate_limiter:
            self._rate_limiter.acquire()
        resp = self._client.get(url)
        resp.raise_for_status()
        return resp.content

    def close(self) -> None:
        self._client.close()


