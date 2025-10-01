from __future__ import annotations

import subprocess
import os
import json
import diskcache as dc


def run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
	return subprocess.run(["cve_collector", *args], capture_output=True, text=True, env=env)


def test_cli_detail_missing_arg_exits_2():
	cp = run_cli(["detail"])  # missing ghsa_id
	assert cp.returncode == 2
	assert "Missing argument" in cp.stderr


def test_cli_detail_not_found_exits_1():
	cp = run_cli(["detail", "GHSA-not-exist-0000-0000"])
	assert cp.returncode == 1
	assert "Not found" in cp.stdout


def test_cli_detail_help_shows_param():
	cp = run_cli(["detail", "--help"])
	assert cp.returncode == 0
	assert "GHSA identifier" in cp.stdout


def _prepare_cached_advisory(tmp_path, ghsa_id: str) -> None:
	# Ensure cache directory exists with the expected namespace
	cache_dir = os.path.join(str(tmp_path), "github")
	os.makedirs(cache_dir, exist_ok=True)
	cache = dc.Cache(cache_dir)
	try:
		# OSV index entry
		osv_raw = {
			"id": ghsa_id,
			"aliases": ["CVE-2024-99999"],
			"summary": "Summary for E2E test",
		}
		cache.set(f"osv:ghsa:{ghsa_id}", json.dumps(osv_raw).encode("utf-8"))

		# GitHub advisory enrichment entry
		gh_raw = {
			"severity": "HIGH",
			"identifiers": [
				{"type": "GHSA", "value": ghsa_id},
				{"type": "CVE", "value": "CVE-2024-99999"},
			],
			"references": [
				{"url": "https://github.com/acme/widgets/commit/0123456789abcdef0123456789abcdef01234567"},
				{"url": "https://github.com/acme/fooutil"},
				{"url": "https://example.com/proof-of-concept"},
			],
		}
		cache.set(f"gh_advisory:{ghsa_id}", json.dumps(gh_raw).encode("utf-8"))
	finally:
		cache.close()


def test_cli_detail_content_from_cache(tmp_path):
	ghsa = "GHSA-aaaa-bbbb-cccc"
	_prepare_cached_advisory(tmp_path, ghsa)
	env = os.environ.copy()
	env["CVE_COLLECTOR_CACHE_DIR"] = str(tmp_path)
	cp = run_cli(["detail", ghsa], env=env)
	assert cp.returncode == 0
	out = cp.stdout
	assert f"GHSA: {ghsa}" in out
	assert "CVE:  CVE-2024-99999" in out
	assert "Severity: HIGH" in out
	# Repositories section includes parsed repo and url
	assert "Repositories:" in out
	assert "acme/widgets" in out
	assert "https://github.com/acme/widgets" in out
	# Commits section includes short hash and commit url
	assert "Commits:" in out
	assert "acme/widgets@0123456" in out
	assert "https://github.com/acme/widgets/commit/0123456789abcdef0123456789abcdef01234567" in out
	# PoC section includes PoC URL
	assert "PoC:" in out
	assert "https://example.com/proof-of-concept" in out
