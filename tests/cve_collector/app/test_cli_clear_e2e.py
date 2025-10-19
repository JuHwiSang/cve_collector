from __future__ import annotations

import subprocess


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve-collector", *args], capture_output=True, text=True)


def test_cli_clear_exits_zero():
	cp = run_cli(["clear"])
	assert cp.returncode == 0
	assert "Cache cleared" in cp.stdout
