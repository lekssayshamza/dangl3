from dataclasses import replace
from io import StringIO
import json
from unittest.mock import Mock

import dns.resolver
import pytest
from rich.console import Console
from typer.testing import CliRunner

from dangl3.cli import app
from dangl3.models import Classification, ScanConfig
from dangl3.reporting import build_report, render_results
from dangl3.scanner import Scanner

runner = CliRunner()


def scan_response(s3_dns, response):
    resolver, inspector = Mock(), Mock()
    resolver.resolve.return_value = s3_dns
    inspector.inspect.return_value = response
    scanner = Scanner(resolver=resolver, inspector=inspector)
    results = scanner.scan(["Blog.Example.com."])
    return scanner, results


@pytest.mark.parametrize("changes, expected", [
    ({"redirects": ["http://blog.example.com/new"]}, Classification.SUSPICIOUS),
    ({"dns_changed": True}, Classification.SUSPICIOUS),
    ({"conflicts": ["Duplicate evidence header: server"]}, Classification.UNKNOWN),
    ({"body": "NoSuchBucket: The specified bucket does not exist NoSuchKey"}, Classification.UNKNOWN),
    ({"body_truncated": True}, Classification.UNKNOWN),
    ({"headers": {}}, Classification.UNKNOWN),
    ({"errors": ["HTTPS certificate failure before HTTP fallback"]}, Classification.SUSPICIOUS),
])
def test_conflicting_or_incomplete_evidence_caps_findings(s3_dns, missing_bucket, changes, expected):
    scanner, results = scan_response(s3_dns, replace(missing_bucket, **changes))
    assert results[0].classification == expected
    assert results[0].explanation
    categories = {evidence.category.value for evidence in results[0].structured_evidence}
    assert "DNS_PROVIDER_MATCH" in categories
    assert "DETECTION_LIMITATION" in categories
    if "errors" not in changes:
        assert "HTTP_AMBIGUOUS" in categories


def test_dns_change_without_fingerprint_is_unknown(s3_dns, missing_bucket):
    _, results = scan_response(s3_dns, replace(missing_bucket, body="normal", dns_changed=True))
    assert results[0].classification == Classification.UNKNOWN
    assert "attribution changed" in results[0].explanation


def test_extended_report_preserves_v1_fields_and_adds_timings(s3_dns, missing_bucket):
    scanner, results = scan_response(s3_dns, missing_bucket)
    report = build_report(results, scanner.config, duration_seconds=scanner.duration_seconds,
                          provider_coverage=scanner.database.coverage())
    report = json.loads(json.dumps(report))
    assert report["schema_version"] == 1  # V2 extends V1 without changing field types.
    assert report["duration_seconds"] >= 0 and report["duration_basis"] == "wall_clock"
    assert report["configuration"]["concurrency"] == 5
    assert len(report["provider_coverage"]) == 6
    result = report["results"][0]
    for key in ("hostname", "dns", "provider", "http", "classification", "evidence", "errors", "matched_fingerprints"):
        assert key in result
    assert result["original_hostname"] == "Blog.Example.com."
    assert result["duration_seconds"] >= 0
    assert result["structured_evidence"][0]["category"] == "DNS_PROVIDER_MATCH"
    assert result["explanation"] and result["limitations"]
    assert "body" not in result["http"]


def test_terminal_summary_and_optional_verbose_evidence(s3_dns, missing_bucket):
    scanner, results = scan_response(s3_dns, missing_bucket)
    plain, verbose = StringIO(), StringIO()
    render_results(results, Console(file=plain, width=140, markup=False), duration_seconds=scanner.duration_seconds)
    render_results(results, Console(file=verbose, width=140, markup=False), verbose=True)
    assert "blog.example.com" in plain.getvalue()
    assert "Targets scanned: 1" in plain.getvalue()
    assert "POTENTIAL_TAKEOVER: 1" in plain.getvalue()
    assert "Evidence:" not in plain.getvalue()
    assert "Evidence:" in verbose.getvalue()


@pytest.mark.parametrize("value", ["0", "21", "-1", "1.5", "abc"])
def test_cli_invalid_concurrency(value):
    result = runner.invoke(app, ["scan", "-d", "blog.example.com", "--concurrency", value])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_providers_command_json_and_terminal():
    result = runner.invoke(app, ["providers", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["tool"]["version"] == "0.2.0"
    assert len(report["providers"]) == 6
    assert result.stderr == ""
    result = runner.invoke(app, ["providers", "--verbose"])
    assert result.exit_code == 0 and result.stdout == ""
    assert "DNS only" in result.stderr and "Sources:" in result.stderr


def test_cli_cancellation_has_exit_130_and_no_json_or_report(monkeypatch, tmp_path):
    class CancelledScanner:
        def __init__(self, config):
            pass
        def scan(self, targets):
            raise KeyboardInterrupt()
    monkeypatch.setattr("dangl3.cli.Scanner", CancelledScanner)
    path = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", "-d", "blog.example.com", "--json", "-o", str(path)])
    assert result.exit_code == 130
    assert result.stdout == "" and not path.exists()
    assert "cancelled" in result.stderr


def test_missing_system_resolver_configuration_is_actionable(monkeypatch):
    def fail(config):
        raise dns.resolver.NoResolverConfiguration("fixture")
    monkeypatch.setattr("dangl3.cli.Scanner", fail)
    result = runner.invoke(app, ["scan", "-d", "blog.example.com", "--json"])
    assert result.exit_code == 2
    assert "Error:" in result.stderr and result.stdout == ""


def test_all_package_modules_import_without_running_cli(monkeypatch):
    import importlib
    from pathlib import Path
    import sys
    import dangl3
    monkeypatch.setattr(sys, "argv", ["dangl3", "--must-not-be-parsed-during-import"])
    for path in Path(dangl3.__file__).parent.glob("*.py"):
        importlib.import_module("dangl3." + path.stem)
