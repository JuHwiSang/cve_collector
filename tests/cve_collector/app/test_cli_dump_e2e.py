from __future__ import annotations

import subprocess
import os
import json


def run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve_collector", *args], capture_output=True, text=True, env=env)


def test_cli_dump_missing_arg_exits_2():
	cp = run_cli(["dump"])  # missing selector
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
	# Either ghsa_id field matches, or identifiers contain the GHSA
	ghsa_matches_field = isinstance(first.get("ghsa_id"), str) and first.get("ghsa_id", "").upper() == ghsa.upper()
	ghsa_in_identifiers = False
	idents = first.get("identifiers")
	if isinstance(idents, list):
		for ident in idents:
			if isinstance(ident, dict) and ident.get("type") == "GHSA" and isinstance(ident.get("value"), str):
				if ident["value"].upper() == ghsa.upper():
					ghsa_in_identifiers = True
					break
	assert ghsa_matches_field or ghsa_in_identifiers

	# Expect at least one URL-like field to exist
	assert any(k in first for k in ["url", "html_url", "repository_advisory_url"]) 


