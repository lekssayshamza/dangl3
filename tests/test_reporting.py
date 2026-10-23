from datetime import datetime
import json

import pytest
from rich.console import Console

from dangl3.models import Classification, ScanConfig, TargetResult
from dangl3.reporting import build_report, render_results, report_json, write_report


def test_json_is_serializable_and_never_contains_body(s3_dns, missing_bucket):
    result = TargetResult(s3_dns.hostname, s3_dns, http=missing_bucket,
                          classification=Classification.POTENTIAL_TAKEOVER)
    report = build_report([result], ScanConfig())
    serialized = report_json(report)
    decoded = json.loads(serialized)
    assert decoded["schema_version"] == 1
    assert decoded["tool"] == {"name": "Dangl3", "version": "0.2.0"}
    assert decoded["total_targets"] == 1
    assert decoded["summary"]["POTENTIAL_TAKEOVER"] == 1
    assert sum(decoded["summary"].values()) == 1
    assert "body" not in decoded["results"][0]["http"]
    assert "specified bucket" not in serialized
    assert datetime.fromisoformat(decoded["scan_timestamp"].replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_atomic_report_replaces_existing_file(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text("old")
    report = build_report([], ScanConfig())
    write_report(path, report)
    assert json.loads(path.read_text()) == report
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_failure_preserves_previous_report(tmp_path, monkeypatch):
    path = tmp_path / "scan.json"
    path.write_text("previous")

    def fail(*args):
        raise OSError("fixture replace failure")

    monkeypatch.setattr("dangl3.reporting.os.replace", fail)
    with pytest.raises(OSError):
        write_report(path, {})
    assert path.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_terminal_text_does_not_interpret_untrusted_markup(public_dns):
    from io import StringIO
    output = StringIO()
    console = Console(file=output, markup=False, highlight=False, width=200)
    result = TargetResult("blog.example.com", public_dns, errors=["[link=https://evil.example]click[/link]"])
    render_results([result], console, verbose=True)
    assert "UNKNOWN" in output.getvalue()
    assert "[link=" in output.getvalue()


def test_empty_report_has_all_summary_counts():
    assert build_report([], ScanConfig())["summary"] == {value.value: 0 for value in Classification}
