from __future__ import annotations

"""cve_collector.scripts.cli
=================================
Command-line interface powered by Typer.

Usage examples
--------------
$ cve_collector all --since 2024-01-01           # fetch & cache all data since date
$ cve_collector CVE-2023-12345                  # show metadata for one CVE (fetch if cache missing)
$ cve_collector clear                           # clear all local caches
$ cve_collector GHSA-xxxx-xxxx-xxxx             # fetch single advisory
"""

from typing import Optional
from dataclasses import asdict
import json
import logging
from enum import Enum

import typer
from typing_extensions import Annotated

from cve_collector import CVECollector
import os
from cve_collector.utils import helpers

try:
    import dotenv 
    dotenv.load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
#
# NOTE: We do not define path constants at the module level.
# This is because pytest's monkeypatching of helper functions needs to happen
# *before* these paths are resolved. Instead, we call the helper functions
# dynamically within the functions that need them.
#
# Typer application ---------------------------------------------------------
app = typer.Typer(add_completion=False, help="CVE Collector")


class LogLevel(str, Enum):
    OFF = "OFF"          # 특수값: 로깅 끔
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"  # 'WARN'도 별칭으로 인식됨
    INFO = "INFO"
    DEBUG = "DEBUG"
    NOTSET = "NOTSET"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _clear_all_caches():
    """Safely clear local caches and metadata file without removing directories."""
    removed_cache, removed_data = CVECollector.clear_local_state()
    typer.echo(f"Local caches cleared. Cache entries≈{removed_cache}, data items={removed_data}.")


def _echo_key_values(obj: dict):
    """Print mapping as `key: value` lines. Lists/dicts as compact JSON."""
    for key, value in obj.items():
        if isinstance(value, (list, dict)):
            rendered = json.dumps(value, ensure_ascii=False, default=str)
        else:
            rendered = str(value)
        typer.echo(f"{key}: {rendered}")
# ---------------------------------------------------------------------------
# Global options / logging setup
# ---------------------------------------------------------------------------


@app.callback()
def main(
    log_level: Annotated[
        Optional[LogLevel],
        typer.Option(
            "--log-level",
            help="Set log level (OFF, CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET). Default: OFF",
        ),
    ] = None,
) -> None:
    """Root command callback to configure logging if requested."""
    # OFF(또는 미지정)이면 아무 설정도 하지 않음
    if log_level in (None, LogLevel.OFF):
        return

    # 이름→정수 매핑 (WARN/CRITICAL 등의 별칭 포함); 잘못된 값은 INFO로 폴백
    try:
        level_name = log_level.value if isinstance(log_level, LogLevel) else str(log_level)
        level = logging.getLevelNamesMapping().get(level_name.upper(), logging.INFO)
    except Exception:
        level = logging.INFO

    # Configure the package logger derived from this module name
    if __package__:
        package_name = __package__.split(".", 1)[0]
    else:
        package_name = "cve_collector"
    logger = logging.getLogger(package_name)

    # 콘솔 핸들러(스트림) 중복 추가 방지
    has_stream = any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    if not has_stream:
        handler = logging.StreamHandler()  # 기본: sys.stderr
        handler.setFormatter(logging.Formatter("%(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(handler)

    # 루트 핸들러로의 전파를 끄면 이 로거에서만 출력되어 중복 방지
    logger.propagate = False
    logger.setLevel(level)





# ---------------------------------------------------------------------------
# Primary command
# ---------------------------------------------------------------------------

@app.command()
def run(
    identifier: str = typer.Argument("all", help="'all' to fetch every CVE, or specific CVE/ GHSA identifier"),
    since: Optional[str] = typer.Option(None, "--since", help="YYYY-MM-DD 이후 CVE 필터 (only used when identifier == 'all')"),
):
    """Fetch & cache vulnerability metadata.

    identifier:
        * all  – fetch metadata for all vulnerabilities (subject to --since)
        * CVE-XXXX-YYYY  – print metadata for that CVE (fetch if necessary)
        * GHSA-xxxx-xxxx-xxxx – same as above for GHSA ID
    """
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        typer.echo("GITHUB_TOKEN is required. Set it in your environment or .env file.")
        raise typer.Exit(code=2)
    collector = CVECollector(github_token)
    if identifier.lower() == "all":
        try:
            results = collector.collect_identifiers(since=since)
        except Exception as e:
            typer.echo(f"Failed to fetch all: {e}")
            raise typer.Exit(code=1)
        # Pretty: one identifier per line
        for ident in results:
            typer.echo(ident)
        typer.echo(f"Total: {len(results)}")
        return

    # single identifier path — fetch live and output JSON
    try:
        obj = collector.collect_one(identifier)
    except Exception as e:
        typer.echo(f"Failed to fetch identifier '{identifier}': {e}")
        raise typer.Exit(code=1)
    # Pretty: key: value per line
    _echo_key_values(asdict(obj))
    return


@app.command()
def clear():
    """Delete local cache directory and metadata file without fetching anything."""
    _clear_all_caches()
