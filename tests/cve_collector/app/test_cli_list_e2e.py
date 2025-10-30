from __future__ import annotations

import subprocess


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve-collector", *args], capture_output=True, text=True)


def test_cli_list_runs_default():
    # Since ecosystem is now optional (defaults to all), but requires cache to be populated,
    # we test with an explicit ecosystem to trigger auto-ingest
    cp = run_cli(["list", "--ecosystem", "npm"])
    assert cp.returncode == 0


def test_cli_list_runs_with_options():
	cp = run_cli(["list", "--ecosystem", "npm", "--limit", "1"])
	assert cp.returncode == 0


def test_cli_list_with_filter():
	cp = run_cli(["list", "--ecosystem", "npm", "--filter", "has_cve"])
	assert cp.returncode == 0


def test_cli_list_with_filter_complex():
	cp = run_cli(["list", "--ecosystem", "npm", "--filter", 'severity == "HIGH"'])
	assert cp.returncode == 0


def test_cli_list_with_filter_invalid():
	cp = run_cli(["list", "--ecosystem", "npm", "--filter", "invalid syntax !"])
	assert cp.returncode == 1
	assert "Filter error" in cp.stderr


def test_cli_list_with_skip():
	"""Test skip parameter works."""
	cp = run_cli(["list", "--ecosystem", "npm", "--skip", "5"])
	assert cp.returncode == 0


def test_cli_list_with_skip_and_limit():
	"""Test skip with limit parameter."""
	cp = run_cli(["list", "--ecosystem", "npm", "--skip", "2", "--limit", "3"])
	assert cp.returncode == 0


def test_cli_list_with_skip_and_filter():
	"""Test skip with filter parameter."""
	cp = run_cli(["list", "--ecosystem", "npm", "--skip", "1", "--filter", "has_cve"])
	assert cp.returncode == 0
