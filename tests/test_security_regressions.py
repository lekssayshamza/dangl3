"""V2 audit regressions; original V1 tests remain alongside these."""

from unittest.mock import Mock

import dns.name
import httpx
import pytest

from dangl3.dns_resolver import DNSResolver
from dangl3.http_client import HTTPInspector
from dangl3.inputs import load_targets, normalize_hostname
from dangl3.models import DNSStatus, ScanConfig
from dangl3.network_safety import is_public_address


@pytest.mark.parametrize("address", [
    "168.63.129.16", "192.0.0.8", "192.0.0.192", "192.88.99.1",
    "100.100.100.200", "64:ff9b::a00:1", "64:ff9b:1::a00:1",
    "2606:4700:4700::1111%lo", "3fff::1", "not-an-ip",
])
def test_explicit_special_destinations_are_blocked(address):
    assert not is_public_address(address)


def test_dns_canonical_name_change_is_not_a_recorded_provider_match():
    answer = Mock()
    answer.canonical_name = dns.name.from_text("changed.example.net.")
    backend = Mock()

    def query(hostname, kind, **kwargs):
        if kind == "CNAME":
            import dns.resolver
            raise dns.resolver.NoAnswer()
        return answer

    backend.resolve.side_effect = query
    result = DNSResolver(resolver=backend).resolve("blog.example.com")
    assert result.status == DNSStatus.ERROR
    assert "CNAME changed" in " ".join(result.errors)


@pytest.mark.parametrize("target", ["bad_name.github.io", "bad\\host.github.io", "host..github.io"])
def test_invalid_dns_cname_is_rejected(fake_dns, target):
    result = DNSResolver(resolver=fake_dns({("blog.example.com", "CNAME"): [target]})).resolve("blog.example.com")
    assert result.status == DNSStatus.ERROR


def test_dns_address_family_mismatch_prevents_request(public_dns):
    public_dns.a = ["2606:4700:4700::1111"]
    resolver = Mock()
    resolver.resolve.return_value = public_dns
    transport = httpx.MockTransport(lambda r: pytest.fail("invalid DNS must not be fetched"))
    result = HTTPInspector(ScanConfig(), resolver, transport).inspect("blog.example.com")
    assert not result.attempts
    assert "family mismatch" in result.errors[0]


@pytest.mark.parametrize("hostname", ["ex\u200bample.com", "bad\u00ad.example.com", "a\u202e.example.com"])
def test_invisible_hostname_characters_cannot_change_authorized_scope(hostname):
    with pytest.raises(ValueError):
        normalize_hostname(hostname)


def test_oversized_line_is_rejected_without_loading_whole_file(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("#" + "a" * 5000)
    with pytest.raises(ValueError, match="limit"):
        load_targets(path)


def test_oversized_target_file_is_rejected(tmp_path):
    path = tmp_path / "targets.txt"
    with path.open("wb") as output:
        output.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="16 MiB"):
        load_targets(path)


def test_truncated_rule_without_negative_conditions_never_matches(database):
    from dangl3.models import HTTPResult
    provider = next(p for p in database.providers if p.id == "vercel")
    assert not database.match(provider, HTTPResult(status_code=404, body="DEPLOYMENT_NOT_FOUND",
                                                  complete=True, body_truncated=True))
