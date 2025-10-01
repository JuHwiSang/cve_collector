from __future__ import annotations

import subprocess


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve_collector", *args], capture_output=True, text=True)


def test_cli_help_shows_commands():
	cp = run_cli(["--help"])
	assert cp.returncode == 0
	assert "list" in cp.stdout
	assert "detail" in cp.stdout
	assert "clear" in cp.stdout


def test_cli_list_runs_default():
	cp = run_cli(["list"])  # default ecosystem/limit
	assert cp.returncode == 0


def test_cli_list_runs_with_options():
	cp = run_cli(["list", "--ecosystem", "npm", "--limit", "1"])
	assert cp.returncode == 0
