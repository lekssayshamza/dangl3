from dataclasses import replace
from unittest.mock import Mock

import pytest

from dangl3.fingerprints import FingerprintDatabase
from dangl3.models import Classification, DNSResult, DNSStatus, HTTPResult
from dangl3.scanner import Scanner


def scan_one(dns_result, http_result=None, database=None):
    resolver, inspector = Mock(), Mock()
    resolver.resolve.return_value = dns_result
    inspector.inspect.return_value = http_result
    scanner = Scanner(resolver=resolver, inspector=inspector, database=database)
    return scanner.scan([dns_result.hostname])[0]


def test_potential_takeover_requires_specific_evidence(s3_dns, missing_bucket):
    result = scan_one(s3_dns, missing_bucket)
    assert result.classification == Classification.POTENTIAL_TAKEOVER
    assert result.matched_fingerprints == ["s3-website-no-such-bucket"]
    assert "claimability has not been verified" in " ".join(result.evidence)


def test_generic_404_never_is_positive(s3_dns):
    result = scan_one(s3_dns, HTTPResult(status_code=404, body="Not Found", complete=True))
    assert result.classification == Classification.NO_EVIDENCE
    assert not result.matched_fingerprints


@pytest.mark.parametrize("status", [200, 403, 404, 410])
def test_harmless_http_responses(s3_dns, status):
    result = scan_one(s3_dns, HTTPResult(status_code=status, body="ordinary page", complete=True))
    assert result.classification == Classification.NO_EVIDENCE


def test_unknown_provider(public_dns):
    assert scan_one(public_dns).classification == Classification.UNKNOWN


def test_nxdomain_alone_is_not_takeover():
    result = scan_one(DNSResult("missing.example.com", DNSStatus.NXDOMAIN))
    assert result.classification == Classification.NO_EVIDENCE


@pytest.mark.parametrize("status", [DNSStatus.NXDOMAIN, DNSStatus.NO_RECORDS])
def test_missing_provider_cname_is_only_suspicious(s3_dns, status):
    s3_dns.status, s3_dns.a = status, []
    result = scan_one(s3_dns)
    assert result.classification == Classification.SUSPICIOUS
    assert not result.matched_fingerprints


@pytest.mark.parametrize("status", [DNSStatus.TIMEOUT, DNSStatus.ERROR, DNSStatus.LOOP,
                                    DNSStatus.MAX_DEPTH, DNSStatus.PARTIAL])
def test_dns_failure_cannot_be_positive(s3_dns, missing_bucket, status):
    s3_dns.status = status
    assert scan_one(s3_dns, missing_bucket).classification == Classification.UNKNOWN


def test_http_failure_is_unknown(s3_dns):
    result = scan_one(s3_dns, HTTPResult(errors=["TLS error"]))
    assert result.classification == Classification.UNKNOWN
    assert result.errors == ["TLS error"]


def test_provider_without_maintained_rule_is_unknown(s3_dns):
    s3_dns.cname_chain = ["owner.github.io"]
    result = scan_one(s3_dns, HTTPResult(status_code=404, body="There isn't a GitHub Pages site here.", complete=True))
    assert result.classification == Classification.UNKNOWN


def test_vercel_missing_deployment_is_only_suspicious(s3_dns):
    s3_dns.cname_chain = ["project.vercel.app"]
    result = scan_one(s3_dns, HTTPResult(status_code=404, body="DEPLOYMENT_NOT_FOUND", complete=True))
    assert result.classification == Classification.SUSPICIOUS


def test_experimental_rule_cannot_produce_potential(database, s3_dns, missing_bucket):
    provider = next(p for p in database.providers if p.id == "aws_s3_website")
    provider = replace(provider, fingerprints=(replace(provider.fingerprints[0], experimental=True),))
    result = scan_one(s3_dns, missing_bucket, FingerprintDatabase([provider]))
    assert result.classification == Classification.SUSPICIOUS


def test_direct_provider_url_is_not_customer_dangling_dns(s3_dns, missing_bucket):
    s3_dns.hostname = s3_dns.cname_chain[0]
    s3_dns.cname_chain = []
    assert scan_one(s3_dns, missing_bucket).classification == Classification.SUSPICIOUS


def test_ambiguous_chain_does_not_choose_one_provider(s3_dns):
    s3_dns.cname_chain.append("app.netlify.app")
    assert scan_one(s3_dns).classification == Classification.UNKNOWN


@pytest.mark.parametrize("http", [
    HTTPResult(status_code=503, complete=True),
    HTTPResult(status_code=404, complete=True, body_truncated=True),
])
def test_incomplete_or_server_errors_are_unknown(s3_dns, http):
    assert scan_one(s3_dns, http).classification == Classification.UNKNOWN


def test_multiple_targets_deduplicate_and_isolate_unexpected_failure(caplog, public_dns):
    resolver, inspector = Mock(), Mock()
    resolver.resolve.side_effect = [RuntimeError("fixture crash"), public_dns]
    scanner = Scanner(resolver=resolver, inspector=inspector)
    results = scanner.scan(["BROKEN.example.com.", "broken.example.com", "blog.example.com"])
    assert len(results) == 2
    assert "RuntimeError" in results[0].errors[0]
    assert results[1].hostname == "blog.example.com"
    assert "Unexpected scan failure" in caplog.text


def test_batch_validated_before_network(public_dns):
    resolver = Mock()
    with pytest.raises(ValueError):
        Scanner(resolver=resolver).scan(["blog.example.com", "invalid/path"])
    resolver.resolve.assert_not_called()
