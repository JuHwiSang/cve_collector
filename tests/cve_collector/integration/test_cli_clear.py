"""tests/test_cli_clear.py

Tests for the `clear` subcommand.
"""

from typer.testing import CliRunner
import diskcache as dc

from cve_collector.cli import app
from cve_collector.utils import helpers


def test_cli_clear_safely_empties_cache_and_top_files(runner: CliRunner, tmp_dirs):
    """
    Verify that `cve_collector clear` clears diskcache sub-caches and removes
    only top-level files in data_dir while keeping directories intact.
    """
    cache_dir, data_dir = tmp_dirs

    # 1) Prepare a diskcache sub-cache
    github_cache_dir = cache_dir / "github"
    github_cache_dir.mkdir(parents=True, exist_ok=True)
    c = dc.Cache(str(github_cache_dir), timeout=1)
    c.set("k", "v")
    c.close()

    # 2) Prepare data_dir: top-level file and a nested directory that must remain
    meta = helpers.get_data_dir() / "cve-meta.json"
    meta.write_text("{}")
    nested = data_dir / "CVE-2024-0001"
    nested.mkdir(parents=True, exist_ok=True)   
    (nested / "info.json").write_text("{\"ok\":true}")

    # Preconditions
    assert meta.exists()
    assert nested.exists()
    # Ensure cache returns the value before clear
    with dc.Cache(str(github_cache_dir), timeout=1) as check:
        assert check.get("k") == "v"

    # 3) Execute clear
    result = runner.invoke(app, ["clear"])

    # 4) Assertions
    assert result.exit_code == 0
    assert "Local caches cleared" in result.stdout

    # data_dir: top-level file removed, directory preserved
    assert not meta.exists()
    assert nested.exists()
    assert (nested / "info.json").exists()

    # cache subdir remains, but entries cleared
    assert github_cache_dir.exists()
    with dc.Cache(str(github_cache_dir), timeout=1) as check:
        assert check.get("k") is None


def test_cli_clear_handles_non_existent_directories(runner: CliRunner, tmp_dirs):
    """
    Verify `cve_collector clear` runs without error if directories are already missing.
    """
    cache_dir, data_dir = tmp_dirs

    # 1. Setup: Ensure directories do not exist
    cache_dir.rmdir()
    data_dir.rmdir()
    assert not cache_dir.exists()
    assert not data_dir.exists()

    # 2. Execute: Run the clear command
    result = runner.invoke(app, ["clear"])

    # 3. Assert: Check that it completed successfully
    assert result.exit_code == 0
    assert "Local caches cleared" in result.stdout
