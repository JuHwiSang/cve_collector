from __future__ import annotations

import subprocess
import os
import json


def run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve_collector", *args], capture_output=True, text=True, env=env)


def test_cli_dump_missing_arg_exits_2():
	cp = run_cli(["dump"])  # missing id
	assert cp.returncode == 2
	assert "Missing argument" in cp.stderr


def test_cli_dump_network_e2e(tmp_path):
	ghsa = "GHSA-2234-fmw7-43wr"
	env = os.environ.copy()
	env["CVE_COLLECTOR_CACHE_DIR"] = str(tmp_path)
	cp = run_cli(["dump", ghsa], env=env)
	assert cp.returncode == 0

	# Output should be a JSON array of provider payloads
	out = cp.stdout
	data = json.loads(out)
	assert isinstance(data, list)
	assert len(data) >= 1
	for item in data:
		assert isinstance(item, dict)

	first = data[0]
	# OSV payload should have id and summary
	assert first.get("id") == ghsa
	assert "summary" in first and isinstance(first["summary"], str)
	# Aliases may contain CVE
	aliases = first.get("aliases")
	if isinstance(aliases, list):
		assert any(isinstance(a, str) and a.startswith("CVE-") for a in aliases)
	# References list contains URLs
	refs = first.get("references")
	if isinstance(refs, list) and len(refs) > 0:
		assert any(isinstance(r, dict) and isinstance(r.get("url"), str) for r in refs)


