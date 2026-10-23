import asyncio
from dataclasses import replace
from importlib.resources import as_file, files
import socket
import ssl

import dns.asyncquery
import dns.message
import dns.rcode
import httpx
import pytest

from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.models import Classification, DNSStatus
from dangl3.network_safety import UnsafeDestination, is_public_address, pin_url
from dangl3.scanner import Scanner
from integration_lab.runner import LocalLab
from integration_lab.scenarios import SCENARIOS


@pytest.mark.parametrize("concurrency", [1, 2, 3, 20])
def test_all_real_socket_scenarios_order_concurrency_and_cleanup(block_network, concurrency):
    async def scenario():
        async with LocalLab(concurrency) as lab:
            block_network.allow(lab)
            results = await lab.scan()
            checks = lab.check_results(results)
            assert len(checks) == 12
            assert all(check.passed for check in checks), checks
            invariants = lab.invariants(results)
            assert all(invariants.values()), invariants
            assert any(query.record_type == "AAAA" for query in lab.dns.queries)
            assert all(request.method == "GET" and "Dangl3/0.2.0" in request.user_agent for request in lab.http.requests)
            assert len(lab.scope.transports) == 10
            assert lab.scanner.config.concurrency == concurrency
        assert lab.cleanup_ok()
        # Bind the same listener ports after shutdown to verify release.
        for scheme, endpoint in lab.http.endpoints.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(endpoint)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(lab.dns.address)
    asyncio.run(scenario())


def test_real_udp_dns_is_authoritative_without_forwarding(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            for name, kind, expected in [
                ("missing-s3.dangl3.test", "CNAME", dns.rcode.NOERROR),
                ("missing-s3.dangl3.test", "MX", dns.rcode.NOERROR),
                ("missing-s3.dangl3.test", "AAAA", dns.rcode.NOERROR),
                ("unlisted.dangl3.test", "A", dns.rcode.NXDOMAIN),
                ("example.com", "A", dns.rcode.NXDOMAIN),
            ]:
                query = dns.message.make_query(name, kind)
                response = await dns.asyncquery.udp(query, "127.0.0.1", port=lab.dns.address[1], timeout=2)
                assert response.rcode() == expected
                assert response.flags & dns.flags.AA
                assert not response.flags & dns.flags.RA
                if kind in ("MX", "AAAA"):
                    assert not response.answer
            assert lab.resolver.resolver.nameservers == ["127.0.0.1"]
            assert lab.resolver.resolver.cache is None
            assert not lab.http.requests
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_lab_dns_fails_closed_with_unmodified_production_inspector(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            # Real local DNS + ordinary production transport/policy, without lab privileges.
            result = (await Scanner(lab.config, resolver=lab.resolver).scan_async([SCENARIOS[0].hostname]))[0]
            assert result.classification == Classification.UNKNOWN
            assert result.http.errors and not result.http.attempts
            assert "destination blocked" in result.http.errors[0]
            assert not lab.http.requests and not lab.scope.requests
            assert not is_public_address("127.0.0.1")
            with pytest.raises(UnsafeDestination):
                pin_url(httpx.URL(f"http://{result.hostname}/"), result.hostname, result.dns)
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_policy_requires_exact_matching_installed_transport(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            with pytest.raises(ValueError, match="explicit transport factory"):
                AsyncHTTPInspector(lab.config, lab.resolver, _destination_policy=lab.scope.pin)
            inspector = AsyncHTTPInspector(
                lab.config, lab.resolver,
                transport_factory=lambda: httpx.AsyncHTTPTransport(trust_env=False),
                _destination_policy=lab.scope.pin,
            )
            result = (await Scanner(lab.config, resolver=lab.resolver, inspector=inspector).scan_async([SCENARIOS[0].hostname]))[0]
            assert result.classification == Classification.UNKNOWN
            assert "matching live lab transport" in result.http.errors[0]
            assert not lab.http.requests
        assert lab.cleanup_ok()
    asyncio.run(scenario())


@pytest.mark.parametrize("url", [
    "http://127.0.0.2:12345/", "http://169.254.169.254/", "http://10.0.0.1/",
    "http://93.184.216.34/", "http://[::1]/", "http://127.0.0.1:1/",
    "http://outside.dangl3.test/", "file:///etc/passwd",
])
def test_lab_transport_rejects_private_public_and_other_local_destinations(block_network, url):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            transport = lab.scope.transport_factory()
            request = httpx.Request("GET", url, headers={"Host": SCENARIOS[0].hostname},
                                    extensions={"sni_hostname": SCENARIOS[0].hostname})
            with pytest.raises(UnsafeDestination):
                await transport.handle_async_request(request)
            assert not lab.http.requests and not lab.scope.requests
        assert lab.cleanup_ok()
    asyncio.run(scenario())


@pytest.mark.parametrize("change", [
    {"a": ["127.0.0.2"]}, {"a": ["127.0.0.1", "169.254.169.254"]},
    {"a": ["93.184.216.34"]}, {"aaaa": ["::1"]},
    {"cname_chain": ["other.vercel.app"]}, {"status": DNSStatus.PARTIAL},
])
def test_policy_rejects_changed_dns_and_mixed_answers(block_network, change):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            host = SCENARIOS[0].hostname
            resolved = await lab.resolver.resolve(host)
            transport = lab.scope.transport_factory()
            with pytest.raises(UnsafeDestination):
                lab.scope.pin(httpx.URL(f"http://{host}/"), host, replace(resolved, **change), transport)
            assert not lab.scope.requests
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_transport_rejects_direct_unapproved_replayed_and_non_get_requests(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            host = SCENARIOS[0].hostname
            resolved = await lab.resolver.resolve(host)
            transport = lab.scope.transport_factory()
            endpoint = lab.http.endpoints["http"]
            local = httpx.URL(f"http://{endpoint[0]}:{endpoint[1]}/")
            request = httpx.Request("GET", local, headers={"Host": host}, extensions={"sni_hostname": host})
            with pytest.raises(UnsafeDestination):
                await transport.handle_async_request(request)
            pinned = lab.scope.pin(httpx.URL(f"http://{host}/"), host, resolved, transport)
            assert pinned == local
            post = httpx.Request("POST", local, headers={"Host": host}, extensions={"sni_hostname": host})
            with pytest.raises(UnsafeDestination):
                await transport.handle_async_request(post)
            with pytest.raises(UnsafeDestination):
                await transport.handle_async_request(request)  # Failed POST consumed the permit.
            assert not lab.http.requests
        with pytest.raises(UnsafeDestination):
            lab.scope.transport_factory()
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_other_lab_instance_cannot_borrow_transport_capability(block_network):
    async def scenario():
        async with LocalLab(1) as first:
            block_network.allow(first)
            resolved = await first.resolver.resolve(SCENARIOS[0].hostname)
            transport = first.scope.transport_factory()
            async with LocalLab(1) as second:
                with pytest.raises(UnsafeDestination):
                    second.scope.pin(httpx.URL(f"http://{SCENARIOS[0].hostname}/"), SCENARIOS[0].hostname, resolved, transport)
            assert second.cleanup_ok()
        assert first.cleanup_ok()
    asyncio.run(scenario())


def test_real_tls_rejects_untrusted_ca_and_wrong_hostname(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            endpoint = lab.http.endpoints["https"]
            url = f"https://127.0.0.1:{endpoint[1]}/"
            with as_file(files("integration_lab").joinpath("fixtures/lab-ca.pem")) as ca:
                trusted = ssl.create_default_context(cafile=str(ca))
            for context, name in ((ssl.create_default_context(), SCENARIOS[0].hostname),
                                  (trusted, "outside.other.test")):
                async with httpx.AsyncClient(verify=context, trust_env=False) as client:
                    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED|certificate verify failed"):
                        await client.get(url, extensions={"sni_hostname": name})
            assert not lab.http.requests
            assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_cancellation_closes_real_clients_tasks_and_servers(block_network):
    async def scenario():
        lab = LocalLab(3, hold_responses=True)
        async with lab:
            block_network.allow(lab)
            task = asyncio.create_task(lab.scan())
            try:
                await asyncio.wait_for(lab.gate.ready.wait(), timeout=5)
                assert lab.http.active_requests == 3
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert all(transport.closed for transport in lab.scope.transports)
            assert not any(t.get_name().startswith("dangl3-worker-") for t in asyncio.all_tasks())
        assert lab.cleanup_ok()
        assert not lab.http.errors and not lab.dns.errors
    asyncio.run(scenario())


def test_exception_in_harness_still_releases_servers(block_network):
    async def scenario():
        lab = LocalLab(1)
        with pytest.raises(RuntimeError, match="intentional"):
            async with lab:
                block_network.allow(lab)
                raise RuntimeError("intentional harness failure")
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_test_socket_guard_cannot_escape_to_other_endpoints(block_network):
    for endpoint in (("127.0.0.1", 1), ("127.0.0.2", 12345), ("169.254.169.254", 80), ("93.184.216.34", 80)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with pytest.raises(AssertionError, match="egress forbidden"):
                sock.connect(endpoint)
    with pytest.raises(AssertionError, match="system DNS forbidden"):
        socket.getaddrinfo("outside.example.com", 443)


@pytest.mark.parametrize("tamper", ["host", "sni"])
def test_transport_rejects_host_and_tls_name_tampering(block_network, tamper):
    async def scenario():
        async with LocalLab(1) as lab:
            block_network.allow(lab)
            host = SCENARIOS[0].hostname
            resolved = await lab.resolver.resolve(host)
            transport = lab.scope.transport_factory()
            url = lab.scope.pin(httpx.URL(f"http://{host}/"), host, resolved, transport)
            headers = {"Host": "outside.dangl3.test" if tamper == "host" else host}
            extensions = {"sni_hostname": "outside.dangl3.test" if tamper == "sni" else host}
            with pytest.raises(UnsafeDestination):
                await transport.handle_async_request(httpx.Request("GET", url, headers=headers, extensions=extensions))
            assert not lab.http.requests
        assert lab.cleanup_ok()
    asyncio.run(scenario())


def test_scope_endpoints_cannot_be_reassigned_to_public_services(block_network):
    async def scenario():
        async with LocalLab(1) as lab:
            with pytest.raises(TypeError):
                lab.scope.endpoints["http"] = ("93.184.216.34", 80)
        assert lab.cleanup_ok()
    asyncio.run(scenario())
