from __future__ import annotations

from typing import Mapping, Optional

import httpx


class HttpClient:
    def __init__(self, base_headers: Optional[Mapping[str, str]] = None, timeout_seconds: float = 20.0) -> None:
        self._client = httpx.Client(timeout=timeout_seconds, headers=dict(base_headers or {}))

    def get_json(self, url: str) -> dict:
        resp = self._client.get(url)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError("HttpClient invariant violated: expected JSON object")
        return data

    def post_json(self, url: str, payload: dict) -> dict:
        resp = self._client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError("HttpClient invariant violated: expected JSON object")
        return data

    def close(self) -> None:
        self._client.close()


