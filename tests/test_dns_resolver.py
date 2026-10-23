import dns.exception
import dns.resolver
import pytest

from dangl3.dns_resolver import DNSResolver
from dangl3.models import DNSStatus


def test_cname_chain_and_both_address_families(fake_dns):
    backend = fake_dns({
        ("blog.example.com", "CNAME"): ["alias.example.com."],
        ("alias.example.com", "CNAME"): ["owner.github.io."],
        ("owner.github.io", "A"): ["93.184.216.34"],
        ("owner.github.io", "AAAA"): ["2606:4700:4700::1111"],
    })
    result = DNSResolver(resolver=backend).resolve("blog.example.com")
    assert result.hostname == "blog.example.com"
    assert result.cname_chain == ["alias.example.com", "owner.github.io"]
    assert result.terminal_hostname == "owner.github.io"
    assert result.a == ["93.184.216.34"]
    assert result.aaaa == ["2606:4700:4700::1111"]
    assert result.status == DNSStatus.RESOLVED
    assert result.records["blog.example.com"]["CNAME"] == ["alias.example.com"]
    assert all(call.kwargs["lifetime"] == 5.0 for call in backend.resolve.call_args_list)


def test_cname_loop(fake_dns):
    result = DNSResolver(resolver=fake_dns({
        ("a.example.com", "CNAME"): ["b.example.com."],
        ("b.example.com", "CNAME"): ["a.example.com."],
    })).resolve("a.example.com")
    assert result.status == DNSStatus.LOOP
    assert result.cname_chain == ["b.example.com", "a.example.com"]


def test_depth_limit_preserves_next_record(fake_dns):
    result = DNSResolver(max_depth=1, resolver=fake_dns({
        ("a.example.com", "CNAME"): ["b.example.com."],
        ("b.example.com", "CNAME"): ["c.example.com."],
    })).resolve("a.example.com")
    assert result.status == DNSStatus.MAX_DEPTH
    assert result.cname_chain == ["b.example.com"]
    assert result.records["b.example.com"]["CNAME"] == ["c.example.com"]


def test_exact_depth_is_allowed(fake_dns):
    result = DNSResolver(max_depth=1, resolver=fake_dns({
        ("a.example.com", "CNAME"): ["b.example.com."],
        ("b.example.com", "A"): ["93.184.216.34"],
    })).resolve("a.example.com")
    assert result.status == DNSStatus.RESOLVED


@pytest.mark.parametrize("exception, status", [
    (dns.exception.Timeout(), DNSStatus.TIMEOUT),
    (dns.resolver.NXDOMAIN(), DNSStatus.NXDOMAIN),
    (dns.resolver.NoNameservers(), DNSStatus.ERROR),
])
def test_dns_errors(fake_dns, exception, status):
    result = DNSResolver(resolver=fake_dns({
        ("blog.example.com", "CNAME"): exception,
    })).resolve("blog.example.com")
    assert result.status == status
    assert result.errors


def test_noanswer_is_not_nxdomain(fake_dns):
    result = DNSResolver(resolver=fake_dns({})).resolve("blog.example.com")
    assert result.status == DNSStatus.NO_RECORDS
    assert not result.errors
    assert result.records["blog.example.com"] == {"CNAME": [], "A": [], "AAAA": []}


def test_partial_address_resolution(fake_dns):
    result = DNSResolver(resolver=fake_dns({
        ("blog.example.com", "A"): ["93.184.216.34"],
        ("blog.example.com", "AAAA"): dns.exception.Timeout(),
    })).resolve("blog.example.com")
    assert result.status == DNSStatus.PARTIAL
    assert result.a
    assert result.errors


def test_dangling_chain_kept_on_nxdomain(fake_dns):
    result = DNSResolver(resolver=fake_dns({
        ("blog.example.com", "CNAME"): ["missing.azurewebsites.net."],
        ("missing.azurewebsites.net", "CNAME"): dns.resolver.NXDOMAIN(),
    })).resolve("blog.example.com")
    assert result.cname_chain == ["missing.azurewebsites.net"]
    assert result.status == DNSStatus.NXDOMAIN


def test_multiple_cnames_are_invalid(fake_dns):
    result = DNSResolver(resolver=fake_dns({
        ("blog.example.com", "CNAME"): ["a.example.com", "b.example.com"],
    })).resolve("blog.example.com")
    assert result.status == DNSStatus.ERROR
