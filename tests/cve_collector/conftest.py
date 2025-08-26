"""tests/conftest.py

Common fixtures for the entire test suite.
"""

import json
import shutil
import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

# Make utils importable
from cve_collector.utils import helpers


@pytest.fixture(scope="session")
def runner() -> CliRunner:
    """Provides a Typer CliRunner instance."""
    return CliRunner()


@pytest.fixture(autouse=True)
def tmp_dirs(tmp_path: Path, monkeypatch):
    """
    Redirects cache and data directories to a temporary location for test isolation.
    This fixture runs automatically for every test function.
    """
    cache_dir = tmp_path / "cache"
    data_dir = tmp_path / "data"

    # Ensure dirs exist for tests that might need them pre-created
    cache_dir.mkdir()
    data_dir.mkdir()

    monkeypatch.setattr(helpers, "get_cache_dir", lambda: cache_dir)
    monkeypatch.setattr(helpers, "get_data_dir", lambda: data_dir)

    # Yield the paths in case a test needs them directly
    yield cache_dir, data_dir


@pytest.fixture
def mock_httpx_client(monkeypatch):
    """
    Replaces httpx.Client with a mock that uses a MockTransport.

    Returns a handler function that tests can use to register mock responses.
    """
    responses = {}
    calls_log: list[tuple[str, str]] = []
    original_client = httpx.Client  # --- 원본 클래스 저장 ---

    def add_response(
        url: str,
        method: str = "GET",
        status_code: int = 200,
        json_payload: dict | None = None,
        content: bytes | None = None,
    ):
        """Register a mock response for a given URL and method."""
        if json_payload is not None:
            body = json.dumps(json_payload).encode("utf-8")
        else:
            body = content if content is not None else b""
        responses[(method.upper(), url)] = (status_code, body)

    def mock_transport(request: httpx.Request) -> httpx.Response:
        """The transport logic that returns registered responses or a 404."""
        method = request.method
        url = str(request.url)
        key = (method, url)
        calls_log.append((method, url))
        if key in responses:
            status, body = responses[key]
            # Add a default content-length header to avoid issues with httpx
            headers = {"Content-Length": str(len(body))}
            return httpx.Response(status, content=body, headers=headers)

        return httpx.Response(404, text=f"Mock URL not found: {request.method} {request.url}")

    # Patch httpx.Client to always use our mock transport
    def patched_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(mock_transport)
        return original_client(*args, **kwargs)  # --- 원본 클래스 사용 ---

    monkeypatch.setattr(httpx, "Client", patched_client)
    # expose call log on the returned function
    add_response.calls = calls_log  # type: ignore[attr-defined]
    return add_response


@pytest.fixture
def create_zip_file():
    """Factory fixture to create a zip file in memory containing dummy JSON files."""

    def _create_zip(file_contents: dict[str, dict]) -> bytes:
        """
        Creates a zip archive from a dictionary of filenames and their JSON content.
        
        Args:
            file_contents: e.g., {"GHSA-1234.json": {"id": "GHSA-1234", ...}}
        
        Returns:
            The binary content of the zip file.
        """
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
            for filename, data in file_contents.items():
                zipf.writestr(filename, json.dumps(data))
        zip_buffer.seek(0)
        return zip_buffer.read()

    return _create_zip
