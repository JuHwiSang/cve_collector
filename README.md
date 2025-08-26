## CVE Collector

Collect and print GHSA data as JSON.

### Install
```bash
pip install git+https://github.com/JuHwiSang/cve_collector
```

### Configure token
Set an environment variable:
```bash
# bash/zsh
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN

# PowerShell (persist for future sessions)
setx GITHUB_TOKEN "YOUR_GITHUB_TOKEN"
# PowerShell (current session)
$env:GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
```

### CLI
```bash
# Fetch all identifiers since date (prints identifiers line-by-line, then Total)
cve_collector run all --since 2024-01-01 --log-level INFO

# Single identifier (prints key: value per line)
# CVE is not supported yet
cve_collector run GHSA-xxxx-xxxx-xxxx

# Clear caches
cve_collector clear
```

### From Python
```python
from dataclasses import asdict
from cve_collector import CVECollector

collector = CVECollector(github_token="YOUR_GITHUB_TOKEN")

# 1) List identifiers for usable advisories
ids = collector.collect_identifiers(since="2024-01-01")
print(ids[:5], len(ids))

# 2) Fetch one advisory and its enriched metadata
obj = collector.collect_one("GHSA-xxxx-xxxx-xxxx")
print(asdict(obj))

# 3) Fetch and persist multiple (returns CVE objects)
items = collector.collect(since="2024-01-01")
print(len(items))

# 4) Clear local caches/metadata
removed_cache, removed_data = CVECollector.clear_local_state()
print(removed_cache, removed_data)
```
