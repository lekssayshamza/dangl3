"""No test may accidentally contact the network."""

import socket
from unittest.mock import Mock

import dns.resolver
import pytest

from dangl3.fingerprints import FingerprintDatabase
from dangl3.models import DNSResult, DNSStatus, HTTPResult


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access is forbidden in the offline test suite")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def database():
    return FingerprintDatabase.load()


@pytest.fixture
def fake_dns():
    def factory(records):
        resolver = Mock()

        def resolve(hostname, kind, **kwargs):
            assert hostname.endswith(".")
            assert kwargs["search"] is False
            value = records.get((hostname.rstrip("."), kind), dns.resolver.NoAnswer())
            if isinstance(value, Exception):
                raise value
            return value

        resolver.resolve.side_effect = resolve
        return resolver
    return factory


@pytest.fixture
def public_dns():
    return DNSResult("blog.example.com", DNSStatus.RESOLVED, a=["93.184.216.34"])


@pytest.fixture
def s3_dns():
    return DNSResult("blog.example.com", DNSStatus.RESOLVED,
                     cname_chain=["bucket.s3-website-us-east-1.amazonaws.com"],
                     a=["93.184.216.34"])


@pytest.fixture
def missing_bucket():
    return HTTPResult(final_url="http://blog.example.com/", status_code=404,
                      headers={"server": "AmazonS3"},
                      body="<h1>NoSuchBucket</h1><p>The specified bucket does not exist</p>",
                      complete=True)
