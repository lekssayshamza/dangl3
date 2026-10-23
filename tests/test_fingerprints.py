from dataclasses import replace
import json

import pytest

from dangl3.fingerprints import FingerprintDatabase, FingerprintDatabaseError
from dangl3.models import HTTPResult


def test_specific_missing_bucket_matches(database, missing_bucket):
    provider = next(p for p in database.providers if p.id == "aws_s3_website")
    assert [rule.id for rule in database.match(provider, missing_bucket)] == ["s3-website-no-such-bucket"]


@pytest.mark.parametrize("changes", [
    {"body": "404 Not Found"}, {"status_code": 200}, {"headers": {}},
    {"body": "NoSuchKey: The specified key does not exist"},
    {"body": "NoSuchBucket The specified bucket does not exist NoSuchKey"},
    {"complete": False}, {"body_truncated": True},
])
def test_harmless_or_incomplete_responses_do_not_match(database, missing_bucket, changes):
    provider = next(p for p in database.providers if p.id == "aws_s3_website")
    assert not database.match(provider, replace(missing_bucket, **changes))


def test_headers_are_case_insensitive(database, missing_bucket):
    provider = next(p for p in database.providers if p.id == "aws_s3_website")
    assert database.match(provider, replace(missing_bucket, headers={"Server": "amazons3"}))


def test_vercel_rule_is_suspicious_only(database):
    provider = next(p for p in database.providers if p.id == "vercel")
    matches = database.match(provider, HTTPResult(status_code=404, body="DEPLOYMENT_NOT_FOUND", complete=True))
    assert len(matches) == 1
    assert matches[0].outcome == "suspicious"
    assert not database.match(provider, HTTPResult(status_code=404, body="NOT_FOUND", complete=True))


@pytest.mark.parametrize("content", ["not json", "[]", "{}", '{"schema_version":true,"providers":[]}',
                                       '{"schema_version":1,"providers":[]}',
                                       '{"schema_version":1,"providers":[{}]}'])
def test_invalid_database_is_actionable(tmp_path, content):
    path = tmp_path / "invalid.json"
    path.write_text(content)
    with pytest.raises(FingerprintDatabaseError):
        FingerprintDatabase.load(path)


def test_missing_database_file(tmp_path):
    with pytest.raises(FingerprintDatabaseError):
        FingerprintDatabase.load(tmp_path / "absent.json")


@pytest.mark.parametrize("mutation", [
    {"status_codes": [True]}, {"status_codes": [999]}, {"body_all": []},
    {"headers_all": {"server": 3}}, {"experimental": "false"},
    {"outcome": "certain"}, {"sources": []},
])
def test_invalid_rule_disables_provider_not_relaxes_it(tmp_path, mutation):
    from importlib.resources import files
    raw = json.loads(files("dangl3").joinpath("data/providers.json").read_text())
    raw["providers"][1]["fingerprints"][0].update(mutation)
    path = tmp_path / "providers.json"
    path.write_text(json.dumps(raw))
    loaded = FingerprintDatabase.load(path)
    assert loaded.warnings
    assert "aws_s3_website" not in [p.id for p in loaded.providers]


def test_dynamic_database_accepts_literal_rules(tmp_path):
    raw = {"schema_version": 1, "providers": [{
        "id": "fixture", "name": "Fixture", "dns_suffixes": ["hosting.example"],
        "limitations": "Offline fixture only", "sources": ["https://example.com/docs"],
        "fingerprints": [{
            "id": "fixture-missing", "status_codes": [404], "body_all": ["fixture unavailable"],
            "headers_all": {}, "negative_body": [], "experimental": True,
            "outcome": "potential", "limitations": "Offline fixture", "sources": ["https://example.com/docs"],
        }],
    }]}
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(raw))
    loaded = FingerprintDatabase.load(path)
    assert loaded.match(loaded.providers[0], HTTPResult(status_code=404, body="fixture unavailable", complete=True))
