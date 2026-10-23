import ssl
from unittest.mock import Mock

import httpcore
import httpx
import pytest

from dangl3.http_client import HTTPInspector, is_public_address
from dangl3.models import DNSResult, DNSStatus, ScanConfig


def response(status=200, body=b"ok", headers=None):
    return httpx.Response(status, stream=httpx.ByteStream(body), headers=headers)


def inspector(public_dns, handler, **config):
    resolver = Mock()
    resolver.resolve.return_value = public_dns
    return HTTPInspector(ScanConfig(**config), resolver, httpx.MockTransport(handler)), resolver


def test_pinned_get_preserves_host_sni_and_user_agent(public_dns):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "93.184.216.34"
        assert request.headers["host"] == "blog.example.com"
        assert "Dangl3/0.2.0" in request.headers["user-agent"]
        assert request.headers["accept-encoding"] == "identity"
        assert request.extensions["sni_hostname"] == "blog.example.com"
        return response(404, b"missing", {"Server": "fixture", "Set-Cookie": "secret"})

    client, _ = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert len(calls) == 1
    assert result.final_url == "https://blog.example.com/"
    assert result.body == "missing"
    assert result.headers == {"server": "fixture"}
    assert result.complete


def test_same_host_redirect_is_followed_and_revalidated(public_dns):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return response(302, headers={"location": "/new"}) if len(seen) == 1 else response()

    client, resolver = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert result.complete
    assert result.final_url == "https://blog.example.com/new"
    assert result.redirects == ["https://blog.example.com/new"]
    assert resolver.resolve.call_count == 2


@pytest.mark.parametrize("location", [
    "https://unrelated.example/", "https://evil.blog.example.com/", "http://blog.example.com/",
    "https://127.0.0.1/", "https://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
    "//unrelated.example/", "https://user:pass@blog.example.com/", "https://blog.example.com:8443/",
])
def test_unsafe_redirect_not_requested(public_dns, location):
    calls = []

    def handler(request):
        calls.append(request)
        return response(302, headers={"location": location})

    client, _ = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert len(calls) == 1
    assert not result.complete
    assert result.errors


def test_redirect_dns_rebinding_is_blocked(public_dns):
    client, resolver = inspector(public_dns, lambda r: response(302, headers={"location": "/next"}))
    resolver.resolve.side_effect = [public_dns, DNSResult("blog.example.com", DNSStatus.RESOLVED, a=["127.0.0.1"])]
    result = client.inspect("blog.example.com")
    assert len(result.attempts) == 1
    assert "destination blocked" in result.errors[-1]


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
    "0.0.0.0", "224.0.0.1", "100.64.0.1", "192.0.2.1", "::1", "fc00::1",
    "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "2001:db8::1",
    "fec0::1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
])
def test_internal_and_special_ip_addresses_blocked(public_dns, address):
    public_dns.a.append(address)
    handler = Mock(side_effect=AssertionError("must not request unsafe addresses"))
    client, _ = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert result.errors
    assert not result.attempts
    handler.assert_not_called()
    assert not is_public_address(address)


def test_ipv6_public_address_allowed(public_dns):
    public_dns.a = []
    public_dns.aaaa = ["2606:4700:4700::1111"]
    client, _ = inspector(public_dns, lambda request: response())
    assert client.inspect("blog.example.com").complete


@pytest.mark.parametrize("status", [DNSStatus.TIMEOUT, DNSStatus.NXDOMAIN, DNSStatus.PARTIAL])
def test_incomplete_dns_blocks_http(public_dns, status):
    public_dns.status = status
    client, _ = inspector(public_dns, lambda r: pytest.fail("unsafe DNS must not reach HTTP"))
    assert not client.inspect("blog.example.com").attempts


@pytest.mark.parametrize("error", [httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError])
def test_http_errors_recorded_and_bounded(public_dns, error):
    def handler(request):
        raise error("fixture error", request=request)
    client, _ = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert len(result.attempts) == 2
    assert len(result.errors) == 2
    assert not result.complete


def test_tls_failure_allows_http_fallback_with_evidence(public_dns):
    def handler(request):
        if request.url.scheme == "https":
            raise httpx.ConnectError("certificate verify failed", request=request) from ssl.SSLError("bad certificate")
        return response(404, b"missing")
    client, _ = inspector(public_dns, handler)
    result = client.inspect("blog.example.com")
    assert result.complete
    assert result.final_url == "http://blog.example.com/"
    assert "certificate verify failed" in result.errors[0]


def test_body_cap_stops_consumption_and_closes_stream(public_dns):
    class Stream(httpx.SyncByteStream):
        closed = False
        read_count = 0

        def __iter__(self):
            for _ in range(1000):
                self.read_count += 1
                yield b"abcdefgh"

        def close(self):
            self.closed = True

    stream = Stream()
    client, _ = inspector(public_dns, lambda r: httpx.Response(200, stream=stream), max_body_bytes=16)
    result = client.inspect("blog.example.com")
    assert len(result.body) == 16
    assert result.body_truncated
    assert stream.read_count == 2
    assert stream.closed


def test_compressed_body_is_never_decompressed(public_dns):
    client, _ = inspector(public_dns, lambda r: response(200, b"bomb", {"content-encoding": "gzip"}))
    result = client.inspect("blog.example.com")
    assert not result.complete
    assert result.body == ""
    assert len(result.attempts) == 1


def test_slow_trickle_checks_deadline_on_each_raw_read(public_dns, monkeypatch):
    clock = {"now": 0.0, "reads": 0, "closed": False}

    class Trickle(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(100):
                clock["now"] += 2
                clock["reads"] += 1
                yield b"x"

        def close(self):
            clock["closed"] = True

    monkeypatch.setattr("dangl3.http_client.time.monotonic", lambda: clock["now"])
    client, _ = inspector(public_dns, lambda r: httpx.Response(200, stream=Trickle()))
    result = client.inspect("blog.example.com")
    assert not result.complete
    assert clock["reads"] == 3
    assert clock["closed"]
    assert "deadline exceeded" in result.errors[-1]
    assert len(result.attempts) == 1


def test_redirect_limit_and_loop(public_dns):
    client, _ = inspector(public_dns, lambda r: response(302, headers={"location": "/next"}), max_redirects=0)
    result = client.inspect("blog.example.com")
    assert len(result.attempts) == 1
    assert "limit" in result.errors[0]
    client, _ = inspector(public_dns, lambda r: response(302, headers={"location": "/"}))
    result = client.inspect("blog.example.com")
    assert len(result.attempts) == 1
    assert "loop" in result.errors[0]


def test_http_only_uses_one_scheme(public_dns):
    client, _ = inspector(public_dns, lambda r: response())
    result = client.inspect("blog.example.com", http_only=True)
    assert result.attempts == ["http://blog.example.com/"]


def test_real_transport_pins_tcp_and_verifies_original_tls_hostname(monkeypatch, public_dns):
    """Exercise httpx+httpcore, replacing only the operating-system network backend."""
    events = {}

    class Wire(httpcore.NetworkStream):
        def read(self, max_bytes, timeout=None):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

        def write(self, buffer, timeout=None):
            events["request"] = events.get("request", b"") + buffer

        def close(self):
            events["closed"] = True

        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            events["tls_name"] = server_hostname
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED
            assert ssl_context.check_hostname
            return self

    def connect_tcp(self, host, port, **kwargs):
        events["tcp"] = (host, port)
        return Wire()

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect_tcp)
    resolver = Mock()
    resolver.resolve.return_value = public_dns
    result = HTTPInspector(ScanConfig(), resolver).inspect("blog.example.com")
    assert result.complete
    assert events["tcp"] == ("93.184.216.34", 443)
    assert events["tls_name"] == "blog.example.com"
    assert b"Host: blog.example.com" in events["request"]
    assert events["closed"]
