from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import hashlib
import json
import platformdirs

# Helper functions for disk-based JSON cache -------------------------------------------------

def _mkdir(p: Path):
    """Safely create directory (parents=True, exist_ok=True)."""
    p.mkdir(parents=True, exist_ok=True)


APP_NAME = "cve-collector"


def _ensure_dir(p: Path) -> Path:
    """Ensure directory exists and return it (wrapper around _mkdir)."""
    _mkdir(p)
    return p


def get_cache_dir() -> Path:
    """Return per-user cache directory using platformdirs (creates if absent)."""
    return _ensure_dir(Path(platformdirs.user_cache_dir(APP_NAME)))


def get_data_dir() -> Path:
    """Return per-user data directory (for large JSON/meta files) using platformdirs."""
    return _ensure_dir(Path(platformdirs.user_data_dir(APP_NAME)))


# -----------------------------------------------------------------------------
# Convenience helpers for simple JSON cache files (used by OSV/GitHub clients)
# -----------------------------------------------------------------------------

def get_cache_key(since: Optional[str] = None) -> str:
    """Generate short md5 cache key from optional since-date string."""
    cache_base = f"cve_candidates_{since or 'all'}"
    return hashlib.md5(cache_base.encode()).hexdigest()[:8]


def get_cache_file_path(cache_key: str) -> Path:
    """Return Path to JSON cache file for given key inside .cache directory."""
    return get_cache_dir() / f"cve_candidates_{cache_key}.json"


def is_cache_valid(cache_file: Path, max_age_hours: int = 24) -> bool:
    """Return True iff cache file exists and is newer than max_age_hours."""
    if not cache_file.exists():
        return False
    file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    return file_age < timedelta(hours=max_age_hours)


def save_cache(data: list, cache_file: Path) -> None:
    """Save arbitrary JSON-serialisable list to cache file with timestamp."""
    cache_data = {"timestamp": datetime.now().isoformat(), "data": data}
    cache_file.write_text(json.dumps(cache_data, indent=2, ensure_ascii=False))


def load_cache(cache_file: Path) -> Optional[list]:
    """Load cached list from cache_file. Return None on any error."""
    if not cache_file.exists():
        return None
    try:
        cache_data = json.loads(cache_file.read_text())
        return cache_data.get("data")
    except (json.JSONDecodeError, KeyError):
        return None
