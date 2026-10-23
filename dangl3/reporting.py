"""Terminal rendering and versioned, atomic JSON reports."""

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from rich.console import Console
from rich.table import Table

from dangl3 import __version__
from dangl3.fingerprints import FingerprintDatabase
from dangl3.models import Classification, ScanConfig, TargetResult


def build_report(results: list[TargetResult], config: ScanConfig,
                 warnings: list[str] | None = None, *, duration_seconds: float | None = None,
                 provider_coverage: list[dict] | None = None) -> dict:
    counts = Counter(result.classification.value for result in results)
    return {
        "schema_version": 1,
        "tool": {"name": "Dangl3", "version": __version__},
        "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_targets": len(results),
        "duration_seconds": (duration_seconds if duration_seconds is not None
                             else round(sum(result.duration_seconds for result in results), 6)),
        "duration_basis": "wall_clock" if duration_seconds is not None else "sum_of_target_durations",
        "provider_coverage": (provider_coverage if provider_coverage is not None
                              else FingerprintDatabase.load().coverage()),
        "configuration": {**asdict(config), "redirect_policy": "same_hostname_public_ip_only",
                          "tls_verification": True, "sequential": config.concurrency == 1},
        "summary": {classification.value: counts[classification.value] for classification in Classification},
        "warnings": list(warnings or []) + [f"{result.hostname}: {warning}"
                                           for result in results for warning in result.warnings],
        "errors": [{"hostname": result.hostname, "message": error}
                   for result in results for error in result.errors],
        "results": [result.to_dict() for result in results],
    }


def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def write_report(path: Path, report: dict) -> None:
    """Replace on the same filesystem; preserve an existing report on failure."""
    payload = report_json(report)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as output:
            temporary = output.name
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def render_results(results: list[TargetResult], console: Console, *, verbose: bool = False,
                   duration_seconds: float | None = None) -> None:
    console.print(f"Dangl3 v{__version__}", style="bold cyan")
    console.print("Subdomain Takeover Detection\n")
    colors = {Classification.POTENTIAL_TAKEOVER: "bold red", Classification.SUSPICIOUS: "yellow",
              Classification.NO_EVIDENCE: "green", Classification.UNKNOWN: "dim"}
    table = Table(show_header=True)
    for column in ("Target", "DNS", "Provider", "HTTP", "Finding"):
        table.add_column(column, overflow="fold", no_wrap=column == "Finding")
    for result in results:
        status = result.http.status_code if result.http else None
        table.add_row(result.hostname, result.dns.status.value,
                      result.provider["name"] if result.provider else "Unknown",
                      str(status) if status is not None else "—",
                      result.classification.value, style=colors[result.classification])
    console.print(table)
    for result in results if verbose else []:
        console.print(f"\nTarget: {result.hostname}", style="bold")
        if result.dns.cname_chain:
            console.print("CNAME: " + " → ".join(result.dns.cname_chain))
        console.print("Evidence:")
        for reason in result.evidence:
            console.print(f"- {reason}")
        for error in result.errors:
            console.print(f"- Error: {error}", style="yellow")
        if verbose:
            console.print("DNS records: " + json.dumps(result.dns.records))
            if result.provider:
                console.print("Provider limitations: " + result.provider["limitations"])
            if result.http:
                console.print("HTTP details: " + json.dumps(result.http.to_dict()))
    console.print("\nResource claimability has not been verified. NO_EVIDENCE is not proof of safety.",
                  style="dim")
    counts = Counter(result.classification for result in results)
    duration = duration_seconds if duration_seconds is not None else sum(r.duration_seconds for r in results)
    console.print(f"\nTargets scanned: {len(results)}\nDuration: {duration:.2f}s")
    for classification in Classification:
        console.print(f"{classification.value}: {counts[classification]}")
    console.print(f"Errors: {sum(len(result.errors) for result in results)}")


def render_providers(database: FingerprintDatabase, console: Console, *, verbose: bool = False) -> None:
    console.print(f"Dangl3 v{__version__} — Provider coverage", style="bold cyan")
    table = Table()
    for column in ("Provider", "DNS detection", "HTTP fingerprint", "Reviewed"):
        table.add_column(column)
    for provider in database.providers:
        label = {"yes": "Yes", "limited": "Limited", "dns_only": "DNS only"}[provider.http_coverage]
        table.add_row(provider.name, "Yes", label, provider.last_reviewed or "Not recorded")
    console.print(table)
    if verbose:
        for provider in database.providers:
            console.print(f"\n{provider.name}: {provider.limitations}")
            console.print("Patterns: " + ", ".join(
                ["*." + suffix for suffix in provider.dns_suffixes] + list(provider.dns_exact)))
            console.print("Sources: " + ", ".join(provider.sources))
    console.print("Review dates describe source review, not live claimability verification.", style="dim")
