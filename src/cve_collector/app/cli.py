from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Sequence

import typer

from .container import Container
from ..core.domain.models import Vulnerability
import json


app = typer.Typer(help="CVE Collector")


@contextmanager
def provide_container() -> Iterator[Container]:
    container = Container()
    container.init_resources()
    container.wire(modules=[__name__])
    try:
        yield container
    finally:
        container.shutdown_resources()


@app.command("list", help="List vulnerabilities. Default columns: GHSA, CVE. With -d/--detail: add severity, ecosystem, repo slug, ★stars, size (enriched).")
def list_cmd(
    ecosystem: str | None = typer.Option(None, help="Ecosystem name (e.g., npm). If not specified, lists all ecosystems."),
    limit: int = typer.Option(10, help="Limit number of results (default: 10)"),
    detail: bool = typer.Option(False, "-d", "--detail", help="Enrich and print detailed list"),
    filter: str | None = typer.Option(None, "--filter", "-f", help="Filter expression (e.g., 'stars > 1000', 'severity == \"HIGH\"')"),
) -> None:
    with provide_container() as container:
        uc = container.list_uc()
        try:
            vulns = uc.execute(ecosystem=ecosystem, limit=limit, detailed=detail, filter_expr=filter)
        except ValueError as e:
            typer.echo(f"Filter error: {e}", err=True)
            raise typer.Exit(code=1)
        _print_list(vulns, detail=detail)


@app.command(help=(
    "Show details for id (GHSA-... or CVE-...). Prints: GHSA, CVE, Summary, "
    "Severity, Published, Modified, Repositories ([ecosystem] slug★stars size + URL), Commits "
    "(repo@short_hash + URL), PoC links."
))
def detail(id: str = typer.Argument(..., help="Vulnerability identifier (e.g., GHSA-xxxx or CVE-xxxx)")) -> None:
    with provide_container() as container:
        uc = container.detail_uc()
        v = uc.execute(id)
        if v is None:
            typer.echo("Not found")
            raise typer.Exit(code=1)
        _print_detail(v)


@app.command()
def clear() -> None:
    with provide_container() as container:
        uc = container.clear_cache_uc()
        uc.execute()
        typer.echo("Cache cleared")


@app.command()
def ingest(
    ecosystems: list[str] = typer.Argument(..., help="Ecosystems to ingest (e.g., npm, pypi, go)", metavar="ECOSYSTEM"),
    force: bool = typer.Option(False, help="Re-download and re-index even if cache exists"),
) -> None:
    with provide_container() as container:
        index = container.index()
        total = 0
        for eco in ecosystems:
            if not force:
                existing = index.list(ecosystem=eco, limit=1)
                if len(existing) > 0:
                    typer.echo(f"{eco}: already ingested; skip")
                    continue
            count = index.ingest_zip(eco)
            typer.echo(f"{eco}: ingested {count} entries")
            total += count
        if total == 0 and not force:
            typer.echo("Nothing to ingest")


def _format_size(size_bytes: int | None) -> str:
    """Format size in bytes to human-readable string with appropriate unit."""
    if size_bytes is None:
        return "-"

    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f}GB"


def _print_list(vulns: Sequence[Vulnerability], *, detail: bool = False) -> None:
    """Print a table of vulnerabilities.

    - Default: columns GHSA, CVE
    - With detail=True: columns GHSA, CVE, Severity, Ecosystem, Repository, Stars, Size (requires enrichment)
    """
    if detail:
        print(f"{'GHSA':22} {'CVE':17} {'Severity':10} {'Eco':8} {'Repository':35} {'Stars':>7} {'Size':>10}")
        for v in vulns:
            sev = v.severity.name if v.severity else "-"
            repo = v.repositories[0].slug if v.repositories else "-"
            eco = v.repositories[0].ecosystem if v.repositories and v.repositories[0].ecosystem else "-"
            stars = v.repositories[0].star_count if v.repositories else None
            star_s = f"{stars}" if stars is not None else " -"
            size_bytes = v.repositories[0].size_bytes if v.repositories else None
            size_s = _format_size(size_bytes)
            print(f"{v.ghsa_id:22} {v.cve_id or '-':17} {sev:10} {eco:8} {repo:35} {star_s:>7} {size_s:>10}")
    else:
        print(f"{'GHSA':22} {'CVE':17}")
        for v in vulns:
            print(f"{v.ghsa_id:22} {v.cve_id or '-':17}")


def _print_detail(v: Vulnerability) -> None:
    """Print detailed sections: header, summary/severity, timestamps, repos, commits, PoC."""
    print(f"GHSA: {v.ghsa_id}")
    if v.cve_id:
        print(f"CVE:  {v.cve_id}")
    if v.summary:
        print(f"Summary: {v.summary}")
    if v.severity:
        print(f"Severity: {v.severity.name}")
    if v.published_at:
        print(f"Published: {v.published_at}")
    if v.modified_at:
        print(f"Modified:  {v.modified_at}")
    if v.repositories:
        print("Repositories:")
        for r in v.repositories:
            eco_s = f"[{r.ecosystem}] " if r.ecosystem else ""
            star_s = f" ★{r.star_count}" if r.star_count is not None else ""
            size_s = f" ({_format_size(r.size_bytes)})" if r.size_bytes is not None else ""
            print(f"  - {eco_s}{r.slug or '-'}{star_s}{size_s} ({r.url or '-'})")
    if v.commits:
        print("Commits:")
        for c in v.commits:
            print(f"  - {c.repo.slug or '-'}@{c.short_hash} ({c.url or '-'})")
    if v.poc_urls:
        print("PoC:")
        for url in v.poc_urls:
            print(f"  - {url}")


@app.command("dump", help="Dump raw JSON payloads for id across configured providers (e.g., GHSA-...).")
def dump(id: str = typer.Argument(..., help="Identifier (GHSA-... or CVE-... as supported)")) -> None:
    with provide_container() as container:
        uc = container.dump_uc()
        payloads = uc.execute(id)
        # Print a JSON array of provider payloads
        print(json.dumps(payloads, ensure_ascii=False, indent=2))


if __name__ == "__main__":  # pragma: no cover
    app()


