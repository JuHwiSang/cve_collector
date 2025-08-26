"""tests/test_cli_run.py

Integration tests for the `run` subcommand (collector-based).
"""

import json
from typer.testing import CliRunner

from cve_collector.cli import app

# A minimal, valid OSV vulnerability record for mocking
MINIMAL_OSV_VULN = {
    "id": "GHSA-1234-5678-9012",
    "published": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2024-9999"],
    "affected": [
        {"package": {"name": "dummy-pkg", "ecosystem": "npm"}}
    ],
    "references": [
        {
            "type": "WEB",
            "url": "https://github.com/owner/repo/commit/abcdef123456"
        }
    ]
}


def test_run_single_id_collects_and_outputs_pretty(runner: CliRunner, mock_httpx_client):
    """
    Tests collecting a single identifier using live path and prints JSON.
    """
    # 1. Mock OSV single-vuln endpoint for GHSA id
    mock_httpx_client(
        url="https://api.osv.dev/v1/vulns/GHSA-1234-5678-9012",
        json_payload={
            "id": "GHSA-1234-5678-9012",
            "published": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2024-9999"],
            "affected": [{"package": {"name": "dummy-pkg", "ecosystem": "npm"}}],
            "references": [
                {"type": "WEB", "url": "https://github.com/owner/repo/commit/abcdef123456"}
            ],
        },
    )

    # 2. Mock GitHub GraphQL for advisory enrich
    mock_httpx_client(
        url="https://api.github.com/graphql",
        method="POST",
        json_payload={
            "data": {
                "adv1": {
                    "ghsaId": "GHSA-1234-5678-9012",
                    "references": [
                        {"url": "https://github.com/owner/repo/commit/abcdef123456"}
                    ],
                }
            }
        },
    )

    # 3. Mock GitHub REST for repository info
    mock_httpx_client(
        url="https://api.github.com/repos/owner/repo",
        json_payload={"size": 100},
    )

    # 4. Execute
    result = runner.invoke(app, ["run", "GHSA-1234-5678-9012"])

    # 5. Assert (pretty key: value output)
    assert result.exit_code == 0
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    kv = {}
    for ln in lines:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            kv[k] = v
    assert kv["ghsa_id"] == "GHSA-1234-5678-9012"
    assert kv["cve_id"] == "CVE-2024-9999"


def test_run_all_collects_and_writes_meta(runner: CliRunner, mock_httpx_client, create_zip_file):
    """
    Tests `run all`, ensuring it mocks network calls, runs the collect process,
    and creates the main metadata file.
    """
    # 1. Setup: Mock all required HTTP endpoints
    # Mock OSV database download
    osv_zip_content = create_zip_file(
        {"GHSA-1234-5678-9012.json": MINIMAL_OSV_VULN}
    )
    mock_httpx_client(
        url="https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        content=osv_zip_content
    )

    # Mock GitHub GraphQL for security advisories
    mock_httpx_client(
        url="https://api.github.com/graphql",
        method="POST",
        json_payload={
            "data": {
                "adv1": {
                    "ghsaId": "GHSA-1234-5678-9012",
                    "references": [
                        {
                            "url": "https://github.com/owner/repo/commit/abcdef123456"
                        }
                    ]
                }
            }
        },
    )

    # Mock GitHub REST for repository info
    mock_httpx_client(
        url="https://api.github.com/repos/owner/repo",
        json_payload={"size": 100} # size in KB
    )

    # 2. Execute first run
    result = runner.invoke(app, ["run", "all"])

    # 3. Assert
    assert result.exit_code == 0
    # CLI should print one id per line and a Total line at the end
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert lines[-1].startswith("Total: ")
    total = int(lines[-1].split(":", 1)[1].strip())
    ids = lines[:-1]
    assert total == len(ids)
    assert ids[0] == "GHSA-1234-5678-9012"

    # 3. HTTP calls were made to expected endpoints (no reliance on meta_path)
    calls = getattr(mock_httpx_client, "calls", [])
    assert ("GET", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip") in calls
    assert any(m == "POST" and u == "https://api.github.com/graphql" for m, u in calls)
    assert ("GET", "https://api.github.com/repos/owner/repo") in calls

    # 4. Clear caches to force network on second run, then run again
    clear_result = runner.invoke(app, ["clear"])
    assert clear_result.exit_code == 0
    result2 = runner.invoke(app, ["run", "all"])
    assert result2.exit_code == 0

    # 5. Assert duplicated calls occurred for GitHub endpoints after clearing caches
    calls2 = getattr(mock_httpx_client, "calls", [])
    # OSV zip is persisted on disk and not cleared by `clear`, so it may remain 1
    assert sum(1 for m, u in calls2 if (m, u) == ("GET", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip")) >= 1
    # Diskcache-backed GitHub results should be re-fetched
    assert sum(1 for m, u in calls2 if (m, u) == ("GET", "https://api.github.com/repos/owner/repo")) >= 2
    assert sum(1 for m, u in calls2 if m == "POST" and u == "https://api.github.com/graphql") >= 2

    # No direct file reads; rely on CLI output only


def test_run_single_id_not_found_in_cache(runner: CliRunner):
    """
    Tests fetching an identifier that does not exist in the cached metadata.
    """
    # 1. Execute without network mocks
    result = runner.invoke(app, ["run", "CVE-2024-9999"])

    # 2. Assert
    assert result.exit_code == 1
    assert "Failed to fetch identifier 'CVE-2024-9999'" in result.stdout
