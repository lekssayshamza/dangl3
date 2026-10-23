"""Capability-paired local transport; not a general private-network override."""

from dataclasses import dataclass
from importlib.resources import as_file, files
import ssl
from types import MappingProxyType

import httpx

from dangl3.models import DNSResult, DNSStatus
from dangl3.network_safety import UnsafeDestination, validate_url
from integration_lab.scenarios import BY_HOST


@dataclass(frozen=True)
class WireRequest:
    hostname: str
    scheme: str
    endpoint: tuple[str, int]


class LabScope:
    """One live lab instance; only its concrete endpoints and fixture names."""

    def __init__(self, endpoints: dict[str, tuple[str, int]]) -> None:
        if set(endpoints) != {"http", "https"} or any(
            host != "127.0.0.1" or not 1024 <= port <= 65535 for host, port in endpoints.values()
        ):
            raise ValueError("lab requires exact unprivileged loopback endpoints")
        self.endpoints = MappingProxyType(dict(endpoints))
        self.active = True
        self.transports: list[LabTransport] = []
        self.requests: list[WireRequest] = []
        with as_file(files("integration_lab").joinpath("fixtures/lab-ca.pem")) as ca:
            self.ssl_context = ssl.create_default_context(cafile=str(ca))
        if not self.ssl_context.check_hostname or self.ssl_context.verify_mode != ssl.CERT_REQUIRED:
            raise RuntimeError("lab TLS verification must remain enabled")

    def transport_factory(self) -> "LabTransport":
        if not self.active:
            raise UnsafeDestination("lab scope is closed")
        transport = LabTransport(self)
        self.transports.append(transport)
        return transport

    def pin(self, url: httpx.URL, hostname: str, resolved: DNSResult,
            transport: httpx.AsyncBaseTransport) -> httpx.URL:
        if not self.active or not isinstance(transport, LabTransport) or transport.scope is not self or transport.closed:
            raise UnsafeDestination("matching live lab transport is required")
        validate_url(url, hostname)  # Production same-host, scheme and port checks.
        scenario = BY_HOST.get(hostname)
        if scenario is None or scenario.fixture is None:
            raise UnsafeDestination("hostname is outside the lab scenario allowlist")
        if (resolved.hostname != hostname or resolved.status != DNSStatus.RESOLVED or resolved.errors
                or resolved.cname_chain != [scenario.target] or resolved.a != ["127.0.0.1"] or resolved.aaaa):
            raise UnsafeDestination("lab DNS must retain its exact fixture chain and loopback address")
        endpoint = self.endpoints[url.scheme]
        pinned = url.copy_with(host=endpoint[0], port=endpoint[1])
        transport.authorize(pinned, hostname)
        return pinned

    async def aclose(self) -> None:
        self.active = False
        for transport in self.transports:
            await transport.aclose()


class LabTransport(httpx.AsyncBaseTransport):
    def __init__(self, scope: LabScope) -> None:
        self.scope = scope
        self.closed = False
        self._permit: tuple[str, str] | None = None
        self._inner = httpx.AsyncHTTPTransport(
            verify=scope.ssl_context, trust_env=False, retries=0,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        )

    def _check(self, url: httpx.URL, hostname: str) -> None:
        endpoint = self.scope.endpoints.get(url.scheme)
        if (not self.scope.active or self.closed or endpoint != (url.host, url.port)
                or url.username or url.password or url.query or url.fragment
                or url.path not in ("/", "/after-redirect")
                or hostname not in BY_HOST or BY_HOST[hostname].fixture is None):
            raise UnsafeDestination("transport request is outside this lab's exact endpoints/routes")

    def authorize(self, url: httpx.URL, hostname: str) -> None:
        self._check(url, hostname)
        if self._permit is not None:
            raise UnsafeDestination("unconsumed lab request authorization")
        self._permit = (str(url), hostname)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.headers.get("host", "")
        self._check(request.url, hostname)
        permit, self._permit = self._permit, None
        if (permit != (str(request.url), hostname) or request.method != "GET"
                or len(request.headers.get_list("host")) != 1
                or request.extensions.get("sni_hostname") != hostname):
            raise UnsafeDestination("request lacks matching lab DNS authorization, Host or TLS SNI")
        self.scope.requests.append(WireRequest(hostname, request.url.scheme, (request.url.host, request.url.port)))
        # Real httpx/httpcore TCP and (for HTTPS) TLS. No response mocking, URL
        # forwarding, proxy, trust-store installation or verification bypass.
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        if not self.closed:
            self.closed = True
            self._permit = None
            await self._inner.aclose()
