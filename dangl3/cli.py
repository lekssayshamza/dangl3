"""Dangl3 command-line entry point."""

import logging
from pathlib import Path
import sys
from typing import Annotated

import dns.exception
from rich.console import Console
import typer

from dangl3 import __version__
from dangl3.fingerprints import FingerprintDatabase, FingerprintDatabaseError
from dangl3.inputs import load_targets, normalize_hostname
from dangl3.models import ScanConfig
from dangl3.reporting import build_report, render_providers, render_results, report_json, write_report
from dangl3.scanner import Scanner

app = typer.Typer(help="Conservative subdomain takeover triage for authorized targets.",
                  no_args_is_help=True, pretty_exceptions_enable=False)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Dangl3 {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", callback=version_callback, is_eager=True,
                                              help="Show installed version.")] = False) -> None:
    """Dangl3 — evidence-based DNS and HTTP inspection."""


@app.command()
def scan(
    domain: Annotated[str | None, typer.Option("--domain", "-d", help="One hostname (no URL).")] = None,
    target_list: Annotated[Path | None, typer.Option("--list", "-l", help="UTF-8 hostname file.")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Atomic JSON report path.")] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="DNS query / HTTP inspection timeout (0–120s).")] = 5.0,
    verbose: Annotated[bool, typer.Option("--verbose", help="Include diagnostics on stderr.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Write only JSON to stdout.")] = False,
    max_cname_depth: Annotated[int, typer.Option("--max-cname-depth", help="Maximum CNAME hops (1–50).")] = 10,
    max_redirects: Annotated[int, typer.Option("--max-redirects", help="Maximum same-host redirects (0–10).")] = 3,
    concurrency: Annotated[int, typer.Option("--concurrency", help="Concurrent target workers (1–20).")] = 5,
    version: Annotated[bool, typer.Option("--version", callback=version_callback, is_eager=True,
                                       help="Show installed version.")] = False,
) -> None:
    """Inspect explicit targets. No enumeration, exploitation, or cloud resource claiming."""
    console = Console(stderr=True, markup=False, highlight=False)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    package_logger = logging.getLogger("dangl3")
    package_logger.addHandler(handler)
    previous_level = package_logger.level
    package_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    try:
        if (domain is None) == (target_list is None):
            raise ValueError("provide exactly one of --domain/-d or --list/-l")
        config = ScanConfig(timeout=timeout, max_cname_depth=max_cname_depth,
                            max_redirects=max_redirects, concurrency=concurrency)
        if domain is not None:
            normalize_hostname(domain)
        targets = [domain] if domain is not None else load_targets(target_list, preserve_original=True)
        if output is not None and target_list is not None and output.resolve() == target_list.resolve():
            raise ValueError("the report output must not overwrite the input file")
        scanner = Scanner(config)
        results = scanner.scan(targets)
        report = build_report(results, config, scanner.database.warnings,
                              duration_seconds=scanner.duration_seconds,
                              provider_coverage=scanner.database.coverage())
        if json_output:
            typer.echo(report_json(report), nl=False)
        if output is not None:
            write_report(output, report)
        if not json_output or verbose:
            render_results(results, console, verbose=verbose, duration_seconds=scanner.duration_seconds)
        if output is not None:
            console.print(f"JSON report written to {output}")
    except KeyboardInterrupt:
        console.print("Scan cancelled; active tasks and connections have been closed.")
        raise typer.Exit(code=130) from None
    except (ValueError, OSError, FingerprintDatabaseError, dns.exception.DNSException) as exc:
        console.print(f"Error: {exc}", style="red")
        raise typer.Exit(code=2) from exc
    finally:
        package_logger.removeHandler(handler)
        package_logger.setLevel(previous_level)


@app.command()
def providers(
    verbose: Annotated[bool, typer.Option("--verbose", help="Show patterns, sources and limitations.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Print coverage metadata as JSON.")] = False,
) -> None:
    """Show actual DNS and HTTP capabilities of the bundled provider database."""
    console = Console(stderr=True, markup=False, highlight=False)
    try:
        database = FingerprintDatabase.load()
        if json_output:
            typer.echo(report_json({"tool": {"name": "Dangl3", "version": __version__},
                                    "providers": database.coverage(), "warnings": database.warnings}), nl=False)
        else:
            render_providers(database, console, verbose=verbose)
    except FingerprintDatabaseError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=2) from exc
