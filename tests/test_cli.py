import json

import httpx
import pytest
from typer.testing import CliRunner

from dangl3.cli import app
from dangl3.dns_resolver import DNSResolver
from dangl3.http_client import HTTPInspector
from dangl3.scanner import Scanner

runner = CliRunner()


@pytest.fixture
def mocked_scan(monkeypatch, fake_dns):
    backend = fake_dns({
        ("blog.example.com", "CNAME"): ["blog.example.com.s3-website-us-east-1.amazonaws.com."],
        ("blog.example.com.s3-website-us-east-1.amazonaws.com", "A"): ["93.184.216.34"],
        ("docs.example.com", "CNAME"): ["owner.github.io."],
        ("owner.github.io", "A"): ["93.184.216.34"],
    })

    def factory(config):
        resolver = DNSResolver(config.timeout, config.max_cname_depth, backend)

        def handler(request):
            return httpx.Response(404, headers={"server": "AmazonS3"}, stream=httpx.ByteStream(
                b"NoSuchBucket: The specified bucket does not exist"))

        inspector = HTTPInspector(config, resolver, httpx.MockTransport(handler))
        return Scanner(config, resolver=resolver, inspector=inspector)

    monkeypatch.setattr("dangl3.cli.Scanner", factory)
    return backend


@pytest.mark.parametrize("args", [["--help"], ["scan", "--help"], ["--version"], ["scan", "--version"]])
def test_help_and_version(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "Dangl3" in result.output or "scan" in result.output


@pytest.mark.parametrize("args", [
    ["scan"], ["scan", "-d", "https://blog.example.com/"],
    ["scan", "-d", "blog.example.com", "-l", "input.txt"],
    ["scan", "-l", "nonexistent-file.txt"],
    ["scan", "-d", "blog.example.com", "--timeout", "nan"],
    ["scan", "-d", "blog.example.com", "--timeout", "-1"],
    ["scan", "-d", "blog.example.com", "--max-cname-depth", "0"],
])
def test_invalid_cli_input(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert result.stdout == ""


def test_end_to_end_json_and_atomic_report(mocked_scan, tmp_path):
    source = tmp_path / "targets.txt"
    source.write_text("Blog.Example.com.\ndocs.example.com\nblog.example.com\n")
    output = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", "-l", str(source), "-o", str(output), "--json", "--verbose"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report == json.loads(output.read_text())
    assert report["total_targets"] == 2
    assert report["summary"]["POTENTIAL_TAKEOVER"] == 1
    assert report["summary"]["UNKNOWN"] == 1
    assert report["results"][0]["http"]["status_code"] == 404
    assert "body" not in report["results"][0]["http"]
    assert "Dangl3" in result.stderr
    assert "DEBUG" in result.stderr


def test_json_without_verbose_is_clean(mocked_scan):
    result = runner.invoke(app, ["scan", "-d", "blog.example.com", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["total_targets"] == 1
    assert result.stderr == ""


def test_terminal_results_are_readable(mocked_scan):
    result = runner.invoke(app, ["scan", "-d", "blog.example.com"])
    assert result.exit_code == 0
    assert "POTENTIAL_TAKEOVER" in result.stderr
    assert "claimability has not been verified" in result.stderr


def test_output_cannot_overwrite_input(tmp_path):
    path = tmp_path / "input.txt"
    path.write_text("blog.example.com\n")
    result = runner.invoke(app, ["scan", "-l", str(path), "-o", str(path)])
    assert result.exit_code == 2
    assert path.read_text() == "blog.example.com\n"


def test_report_write_failure_is_actionable(mocked_scan, tmp_path):
    result = runner.invoke(app, ["scan", "-d", "blog.example.com", "-o", str(tmp_path / "absent" / "report.json")])
    assert result.exit_code == 2
    assert "Error:" in result.stderr
