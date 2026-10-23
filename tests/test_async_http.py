import asyncio
from dataclasses import replace
import ssl
from unittest.mock import AsyncMock

import httpcore
import httpx
import pytest

from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.models import ScanConfig


def reply(status=200, body=b"ok", headers=None):
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


def make_inspector(public_dns, handler, **config):
    resolver = AsyncMock()
    resolver.resolve.return_value = public_dns
    inspector = AsyncHTTPInspector(ScanConfig(**config), resolver,
                                   transport_factory=lambda: httpx.MockTransport(handler))
    return inspector, resolver


def test_async_initial_snapshot_avoids_duplicate_dns(public_dns):
    def handler(request):
        assert request.url.host == public_dns.a[0]
        assert request.headers["host"] == "blog.example.com"
        assert request.extensions["sni_hostname"] == "blog.example.com"
        assert "Dangl3/0.2.0" in request.headers["user-agent"]
        return reply()
    inspector, resolver = make_inspector(public_dns, handler)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert result.complete and result.body == "ok"
    assert result.connected_addresses == [public_dns.a[0]]
    resolver.resolve.assert_not_called()


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.100.100.200", "168.63.129.16", "0.0.0.0", "224.0.0.1", "192.0.0.8",
    "::1", "fd00:ec2::254", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "fec0::1",
])
def test_async_private_and_mixed_dns_never_reaches_transport(public_dns, address):
    public_dns.a.append(address)
    inspector, _ = make_inspector(public_dns, lambda r: pytest.fail("unsafe request"))
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert not result.attempts and not result.complete and result.errors


@pytest.mark.parametrize("location", [
    "http://blog.example.com/", "https://unrelated.example/", "//127.0.0.1/",
    "https://169.254.169.254/", "https://[::1]/", "https://blog.example.com:8080/",
    "https://user:pass@blog.example.com/", "file:///etc/passwd",
])
def test_async_unsafe_redirects_are_not_fetched(public_dns, location):
    seen = []
    def handler(request):
        seen.append(request)
        return reply(302, headers={"location": location})
    inspector, _ = make_inspector(public_dns, handler)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert len(seen) == 1 and not result.complete and result.errors


def test_async_rebinding_on_redirect_is_blocked(public_dns):
    inspector, resolver = make_inspector(public_dns, lambda r: reply(302, headers={"location": "/next"}))
    resolver.resolve.return_value = replace(public_dns, a=["127.0.0.1"])
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert len(result.attempts) == 1 and result.errors


def test_async_rebinding_on_http_fallback_is_blocked(public_dns):
    def handler(request):
        raise httpx.ConnectError("certificate error", request=request)
    inspector, resolver = make_inspector(public_dns, handler)
    resolver.resolve.return_value = replace(public_dns, a=["169.254.169.254"])
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert len(result.attempts) == 1 and len(result.errors) == 2


def test_changed_provider_chain_is_recorded(public_dns):
    def handler(request):
        return reply(302, headers={"location": "/next"}) if request.url.path == "/" else reply()
    inspector, resolver = make_inspector(public_dns, handler)
    resolver.resolve.return_value = replace(public_dns, cname_chain=["other.netlify.app"])
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert result.complete and result.dns_changed
    assert len(result.dns_chains) == 2


def test_async_body_cap_closes_stream(public_dns):
    state = {"reads": 0, "closed": False}
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(1000):
                state["reads"] += 1
                yield b"abcdefgh"
        async def aclose(self):
            state["closed"] = True
    inspector, _ = make_inspector(public_dns, lambda r: httpx.Response(200, stream=Stream()), max_body_bytes=16)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert result.body_truncated and result.inspected_bytes == 16
    assert state == {"reads": 2, "closed": True}


def test_absolute_deadline_stops_slow_trickle(public_dns):
    state = {"closed": False}
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.01)
                yield b"a"
        async def aclose(self):
            state["closed"] = True
    inspector, _ = make_inspector(public_dns, lambda r: httpx.Response(200, stream=Stream()), timeout=0.025)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert not result.complete and result.errors and state["closed"]
    assert len(result.attempts) == 1


def test_async_transport_timeouts_are_bounded(public_dns):
    async def handler(request):
        await asyncio.sleep(10)
        return reply()
    inspector, _ = make_inspector(public_dns, handler, timeout=0.01)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert not result.complete and len(result.attempts) == 2
    assert len(result.errors) == 2


def test_async_tls_failure_records_error_before_http_fallback(public_dns):
    def handler(request):
        if request.url.scheme == "https":
            raise httpx.ConnectError("certificate verify failed", request=request)
        return reply()
    inspector, _ = make_inspector(public_dns, handler)
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert result.complete and result.final_url.startswith("http:")
    assert "certificate verify failed" in result.errors[0]


def test_duplicate_location_is_blocked(public_dns):
    inspector, _ = make_inspector(public_dns, lambda r: reply(302, headers=[("location", "/a"), ("location", "/b")]))
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert not result.complete and "duplicate Location" in result.errors[0]


def test_async_duplicate_evidence_headers_are_conflicts(public_dns):
    inspector, _ = make_inspector(public_dns, lambda r: reply(404, headers=[("server", "AmazonS3"), ("server", "other")]))
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert result.conflicts == ["Duplicate evidence header: server"]


def test_async_compression_is_not_decompressed(public_dns):
    inspector, _ = make_inspector(public_dns, lambda r: reply(headers={"content-encoding": "gzip"}))
    result = asyncio.run(inspector.inspect("blog.example.com", initial_dns=public_dns))
    assert not result.complete and not result.body


def test_actual_async_tcp_ip_sni_and_hostname_pool_isolation(monkeypatch, public_dns):
    events = {"tcp": [], "tls": [], "closed": 0}
    class Wire(httpcore.AsyncNetworkStream):
        async def read(self, max_bytes, timeout=None):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        async def write(self, buffer, timeout=None):
            pass
        async def aclose(self):
            events["closed"] += 1
        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED
            assert ssl_context.check_hostname
            events["tls"].append(server_hostname)
            return self
    async def connect_tcp(self, host, port, **kwargs):
        events["tcp"].append((host, port))
        return Wire()
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)
    async def scenario():
        resolver = AsyncMock()
        # An unrestricted second lookup would return a metadata address.
        resolver.resolve.return_value = replace(public_dns, a=["169.254.169.254"])
        inspector = AsyncHTTPInspector(ScanConfig(), resolver)
        first, second = await asyncio.gather(
            inspector.inspect("blog.example.com", initial_dns=public_dns),
            inspector.inspect("docs.example.com", initial_dns=replace(public_dns, hostname="docs.example.com")),
        )
        assert first.complete and second.complete
        resolver.resolve.assert_not_called()
    asyncio.run(scenario())
    assert events["tcp"] == [(public_dns.a[0], 443)] * 2
    assert set(events["tls"]) == {"blog.example.com", "docs.example.com"}
    assert events["closed"] == 2


def test_same_target_safe_redirect_reuses_tcp_connection(monkeypatch, public_dns):
    state = {"connections": 0, "reads": 0}
    class Wire(httpcore.AsyncNetworkStream):
        async def read(self, max_bytes, timeout=None):
            state["reads"] += 1
            if state["reads"] == 1:
                return b"HTTP/1.1 302 Found\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n"
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        async def write(self, buffer, timeout=None):
            pass
        async def aclose(self):
            pass
        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            return self
    async def connect_tcp(self, host, port, **kwargs):
        state["connections"] += 1
        return Wire()
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)
    resolver = AsyncMock()
    resolver.resolve.return_value = public_dns
    result = asyncio.run(AsyncHTTPInspector(ScanConfig(), resolver).inspect("blog.example.com", initial_dns=public_dns))
    assert result.complete and result.final_url.endswith("/new")
    assert state["connections"] == 1
    assert resolver.resolve.call_count == 1  # Redirect still gets fresh DNS validation.
