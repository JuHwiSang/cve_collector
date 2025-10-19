from __future__ import annotations

import subprocess


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve-collector", *args], capture_output=True, text=True)


def test_cli_help_shows_commands():
	cp = run_cli(["--help"])
	assert cp.returncode == 0
	assert "list" in cp.stdout
	assert "detail" in cp.stdout
	assert "clear" in cp.stdout
	assert "dump" in cp.stdout


