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


@app.command("list", help="List vulnerabilities. Default columns: GHSA, CVE. With -d/--detail: add repo slug, ★stars, severity (enriched).")
def list_cmd(
    ecosystem: str = typer.Option("npm", help="Ecosystem name (e.g., npm)"),
    limit: int | None = typer.Option(None, help="Limit number of results"),
    detail: bool = typer.Option(False, "-d", "--detail", help="Enrich and print detailed list"),
) -> None:
    with provide_container() as container:
        uc = container.list_uc()
        vulns = uc.execute(ecosystem=ecosystem, limit=limit, detailed=detail)
        _print_list(vulns, detail=detail)


@app.command(help=(
    "Show details for selector (GHSA-... or CVE-...). Prints: GHSA, CVE, Summary, "
    "Severity, Published, Modified, Repositories (slug★stars + URL), Commits "
    "(repo@short_hash + URL), PoC links."
))
def detail(selector: str = typer.Argument(..., help="Vulnerability identifier (e.g., GHSA-xxxx or CVE-xxxx)")) -> None:
    with provide_container() as container:
        uc = container.detail_uc()
        v = uc.execute(selector)
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


def _print_list(vulns: Sequence[Vulnerability], *, detail: bool = False) -> None:
    """Print a table of vulnerabilities.

    - Default: columns GHSA, CVE
    - With detail=True: columns GHSA, CVE, Repository, Stars, Severity (requires enrichment)
    """
    if detail:
        print(f"{'GHSA':22} {'CVE':17} {'Repository':35} {'Stars':>6} {'Severity'}")
        for v in vulns:
            repo = v.repositories[0].slug if v.repositories else "-"
            stars = v.repositories[0].star_count if v.repositories else None
            star_s = f"★{stars}" if stars is not None else "-"
            sev = v.severity.name if v.severity else "-"
            print(f"{v.ghsa_id:22} {v.cve_id or '-':17} {repo:35} {star_s:>6} {sev}")
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
            star_s = f" ★{r.star_count}" if r.star_count is not None else ""
            print(f"  - {r.slug or '-'}{star_s} ({r.url or '-'})")
    if v.commits:
        print("Commits:")
        for c in v.commits:
            print(f"  - {c.repo.slug or '-'}@{c.short_hash} ({c.url or '-'})")
    if v.poc_urls:
        print("PoC:")
        for url in v.poc_urls:
            print(f"  - {url}")


@app.command("dump", help="Dump raw JSON payloads for selector across configured providers (e.g., GHSA-...).")
def dump(selector: str = typer.Argument(..., help="Identifier (GHSA-... or CVE-... as supported)")) -> None:
    with provide_container() as container:
        uc = container.raw_uc()
        payloads = uc.execute(selector)
        # Print a JSON array of provider payloads
        print(json.dumps(payloads, ensure_ascii=False, indent=2))


if __name__ == "__main__":  # pragma: no cover
    app()


