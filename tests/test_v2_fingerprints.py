from dataclasses import replace
from importlib.resources import files
import json

import pytest

from dangl3.fingerprints import FingerprintDatabase, FingerprintDatabaseError
from dangl3.models import HTTPResult
from dangl3.providers import identify_providers


def original_database():
    return json.loads(files("dangl3").joinpath("data/providers.json").read_text())


@pytest.mark.parametrize("mutation", [
    {"negative_bodi": ["NoSuchKey"]}, {"extra_condition": False},
    {"headers_all": {"Set-Cookie": "secret"}}, {"headers_all": {"bad\nheader": "value"}},
    {"headers_all": {"server": "bad\r\nvalue"}}, {"body_all": ["x" * 4097]},
    {"body_title": 5}, {"sources": ["https://user:password@example.com/source"]},
    {"sources": ["https:///path"]}, {"sources": ["http://example.com/docs"]},
    {"sources": ["https://example.com:bogus/path"]},
])
def test_invalid_untrusted_rules_disable_whole_provider(tmp_path, mutation):
    raw = original_database()
    raw["providers"][1]["fingerprints"][0].update(mutation)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw))
    database = FingerprintDatabase.load(path)
    assert "aws_s3_website" not in {p.id for p in database.providers}
    assert database.warnings


@pytest.mark.parametrize("content", [
    '{"schema_version":1,"schema_version":1,"providers":[]}',
    '{"schema_version":1,"providers":[],"x":NaN}',
    '[' * 2000 + '0' + ']' * 2000,
    ' ' * (1024 * 1024 + 1),
])
def test_oversized_duplicate_or_invalid_json_is_rejected(tmp_path, content):
    path = tmp_path / "rules.json"
    path.write_text(content)
    with pytest.raises(FingerprintDatabaseError):
        FingerprintDatabase.load(path)


@pytest.mark.parametrize("changes", [
    {"last_reviewed": "9999-01-01"}, {"last_reviewed": "not-a-date"},
    {"name": "unsafe\x1b[31m"}, {"dns_exact": ["not a hostname"]},
    {"review_basis": "live_claimability"}, {"surprise": True},
])
def test_invalid_provider_metadata_is_not_exposed(tmp_path, changes):
    raw = original_database()
    raw["providers"][0].update(changes)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw))
    database = FingerprintDatabase.load(path)
    assert "github_pages" not in {p.id for p in database.providers}
    assert database.warnings


@pytest.mark.parametrize("token", ["XDEPLOYMENT_NOT_FOUND", "DEPLOYMENT_NOT_FOUND_SUFFIX", "NoSuchBucketPolicy"])
def test_error_codes_are_bounded_tokens(database, token, missing_bucket):
    if "DEPLOYMENT" in token:
        provider = next(p for p in database.providers if p.id == "vercel")
        response = HTTPResult(status_code=404, body=token, complete=True)
    else:
        provider = next(p for p in database.providers if p.id == "aws_s3_website")
        response = replace(missing_bucket, body=f"{token}: The specified bucket does not exist")
    assert not database.match(provider, response)


def test_new_documented_dns_patterns_and_false_positives(database):
    assert identify_providers(["project.vercel-dns-017.com"], database)[0].id == "vercel"
    assert identify_providers(["apex-loadbalancer.netlify.com"], database)[0].id == "netlify"
    for name in ("x.vercel-dns-017.com.evil.example", "x.vercel-dns-999.com",
                 "evilapex-loadbalancer.netlify.com", "apex-loadbalancer.netlify.com.evil.example"):
        assert not identify_providers([name], database)


def test_optional_html_title_is_an_exact_condition(database):
    rule = next(p for p in database.providers if p.id == "vercel").fingerprints[0]
    rule = replace(rule, body_title="Expected error")
    assert rule.matches(HTTPResult(status_code=404, body="<title>Expected error</title> DEPLOYMENT_NOT_FOUND", complete=True))
    assert not rule.matches(HTTPResult(status_code=404, body="<title>Healthy site</title> DEPLOYMENT_NOT_FOUND", complete=True))


def test_provider_coverage_is_explicit_and_honest(database):
    coverage = database.coverage()
    assert len(coverage) == 6
    assert sum(item["fingerprint_available"] for item in coverage) == 2
    for item in coverage:
        assert item["id"] and item["name"] and item["dns_patterns"]
        assert item["last_reviewed"] == "2026-10-23"
        assert item["limitations"] and item["sources"]
        assert item["live_verified_on"] is None
        assert item["claimability_verified"] is False


def test_long_repeated_literal_keeps_word_boundaries(database):
    rule = next(p for p in database.providers if p.id == "vercel").fingerprints[0]
    literal = "E" * 4096
    rule = replace(rule, body_all=(literal,))
    assert not rule.matches(HTTPResult(status_code=404, body="E" * 65536, complete=True))
    assert rule.matches(HTTPResult(status_code=404, body="[" + literal + "]", complete=True))
    assert not replace(rule, body_all=("",)).matches(HTTPResult(status_code=404, body="word", complete=True))
