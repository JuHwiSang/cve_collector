## CVE Collector

Collect and print GHSA data as JSON.

### Install
```bash
pip install git+https://github.com/your-org/cve_collector.git
```

### CLI
```bash
# All (JSON array)
cve_collector run all --since 2024-01-01

# Single (JSON object)
cve_collector run GHSA-xxxx-xxxx-xxxx

# Clear caches
cve_collector clear
```

### From Python
```python
from cve_collector.scripts.cli import run

result = run('GHSA-1234-1234-1234')

print(result)
```
