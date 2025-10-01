from __future__ import annotations

import json
import httpx
import pytest

from cve_collector.infra.http_client import HttpClient


def _json_response(status_code: int, obj: object) -> httpx.Response:
    req = httpx.Request("GET", "http://test")
    content = json.dumps(obj).encode("utf-8")
    return httpx.Response(status_code, request=req, content=content, headers={"Content-Type": "application/json"})


class _StubClient(httpx.Client):
    def __init__(self, get_resp: httpx.Response, post_resp: httpx.Response) -> None:
        super().__init__(timeout=0.1)
        self._get_resp = get_resp
        self._post_resp = post_resp

    def get(self, url: str):
        return self._get_resp

    def post(self, url: str, json: dict):
        return self._post_resp


def test_http_client_get_json_ok_dict():
    hc = HttpClient()
    hc._client = _StubClient(_json_response(200, {"a": 1}), _json_response(200, {}))
    data = hc.get_json("http://x")
    assert data == {"a": 1}


def test_http_client_get_json_non_object_raises_typeerror():
    hc = HttpClient()
    hc._client = _StubClient(_json_response(200, [1, 2, 3]), _json_response(200, {}))
    with pytest.raises(TypeError):
        hc.get_json("http://x")


def test_http_client_get_json_http_error_raises():
    hc = HttpClient()
    hc._client = _StubClient(_json_response(404, {}), _json_response(200, {}))
    with pytest.raises(httpx.HTTPStatusError):
        hc.get_json("http://x")


def test_http_client_post_json_ok_dict():
    hc = HttpClient()
    hc._client = _StubClient(_json_response(200, {}), _json_response(200, {"ok": True}))
    data = hc.post_json("http://x", {"k": "v"})
    assert data == {"ok": True}


def test_http_client_post_json_non_object_raises_typeerror():
    hc = HttpClient()
    hc._client = _StubClient(_json_response(200, {}), _json_response(200, [1]))
    with pytest.raises(TypeError):
        hc.post_json("http://x", {})
