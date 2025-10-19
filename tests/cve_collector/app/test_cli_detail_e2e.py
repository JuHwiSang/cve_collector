from __future__ import annotations

import subprocess
import os
import re


def run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
	result = subprocess.run(["cve-collector", *args], capture_output=True, text=True, env=env)
	return result


def test_cli_detail_missing_arg_exits_2():
	cp = run_cli(["detail"])  # missing ghsa_id
	assert cp.returncode == 2
	assert "Missing argument" in cp.stderr


def test_cli_detail_not_found_exits_1():
	cp = run_cli(["detail", "GHSA-not-exist-0000-0000"])
	assert cp.returncode == 1
	assert "Not found" in cp.stdout or "Not found" in cp.stderr


def test_cli_detail_help_shows_param():
	cp = run_cli(["detail", "--help"])
	assert cp.returncode == 0
	assert "Vulnerability identifier" in cp.stdout


def test_cli_detail_network_e2e(tmp_path):
	ghsa = "GHSA-2234-fmw7-43wr"
	env = os.environ.copy()
	env["CVE_COLLECTOR_CACHE_DIR"] = str(tmp_path)
	cp = run_cli(["detail", ghsa], env=env)
	assert cp.returncode == 0
	out = cp.stdout
	# Basic header
	assert f"GHSA: {ghsa}" in out

	# CVE and Severity present (severity enum-like)
	assert "CVE:  CVE-" in out or "CVE:" in out  # tolerate missing CVE in edge cases
	sev_match = re.search(r"Severity:\s+(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)", out)
	assert sev_match is not None

	# Timestamps if available
	assert "Published:" in out
	assert "Modified:" in out
	# Loose ISO-like check
	assert re.search(r"Published:\s+\d{4}-\d{2}-\d{2}", out)
	assert re.search(r"Modified:\s+\d{4}-\d{2}-\d{2}", out)

	# Repositories section with expected repo slug/url
	assert "Repositories:" in out
	assert "honojs/hono" in out
	assert "https://github.com/honojs/hono" in out

	# Commits section with short hash and commit URL
	assert "Commits:" in out
	# short hash pattern (12 hex)
	assert re.search(r"@[0-9a-fA-F]{12}\b", out)
	# commit URL pattern
	assert re.search(r"https://github\.com/.+/.+/commit/[0-9a-fA-F]{7,40}", out)
