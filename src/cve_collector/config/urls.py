from __future__ import annotations


def get_osv_vuln_url(ghsa_id: str) -> str:
	return f"https://api.osv.dev/v1/vulns/{ghsa_id}"


def get_osv_zip_url(ecosystem: str) -> str:
	return f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


def get_github_advisory_url(ghsa_id: str) -> str:
	return f"https://api.github.com/advisories/{ghsa_id}"


def get_github_repo_url(owner: str, name: str) -> str:
    return f"https://api.github.com/repos/{owner}/{name}"


