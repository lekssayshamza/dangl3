"""Async HTTP with target-isolated pools and connection-level IP pinning."""

import asyncio
from collections.abc import Callable
import logging
import ssl

import httpx

from dangl3.async_dns_resolver import AsyncDNSResolver
from dangl3.async_utils import invoke
from dangl3.http_client import (EVIDENCE_HEADERS, REDIRECT_CODES, USER_AGENT,
                               record_destination, record_response, redirect_destination)
from dangl3.models import DNSResult, HTTPResult, ScanConfig
from dangl3.network_safety import UnsafeDestination, pin_url, validate_url

logger = logging.getLogger(__name__)


class AsyncHTTPInspector:
    def __init__(self, config: ScanConfig, resolver: AsyncDNSResolver, *,
                 transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
                 evidence_headers: set[str] | None = None,
                 _destination_policy: Callable[[httpx.URL, str, DNSResult, httpx.AsyncBaseTransport], httpx.URL] | None = None) -> None:
        # Internal integration-harness seam. The default transport can never be
        # combined with an alternative destination policy. No CLI/config option
        # exposes this; injected Python transports/policies are trusted code.
        if _destination_policy is not None and transport_factory is None:
            raise ValueError("an internal destination policy requires an explicit transport factory")
        self.config = config
        self.resolver = resolver
        self.transport_factory = transport_factory
        self._destination_policy = _destination_policy
        self.evidence_headers = EVIDENCE_HEADERS | (evidence_headers or set())
        # Read the CA store once, before scanning. TLS settings are never weakened.
        self.ssl_context = ssl.create_default_context()

    async def inspect(self, hostname: str, *, http_only: bool = False,
                      initial_dns: DNSResult | None = None) -> HTTPResult:
        result = HTTPResult()
        transport = (self.transport_factory() if self.transport_factory else httpx.AsyncHTTPTransport(
            verify=self.ssl_context, trust_env=False, retries=0,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        ))
        # Never share IP-keyed pools or cookies between hostnames. Redirects within
        # this target may reuse an already validated connection to the same IP.
        async with httpx.AsyncClient(
            transport=transport, timeout=self.config.timeout,
            follow_redirects=False, trust_env=False,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        ) as client:
            for scheme in (("http",) if http_only else ("https", "http")):
                try:
                    await self._inspect_scheme(client, hostname, scheme, result, initial_dns, transport)
                    return result
                except UnsafeDestination as exc:
                    result.errors.append(f"HTTP destination blocked: {exc}")
                    return result
                except (httpx.HTTPError, TimeoutError, ValueError) as exc:
                    detail = str(exc) or "HTTP request deadline exceeded"
                    result.errors.append(f"{scheme.upper()}: {type(exc).__name__}: {detail}")
                    logger.debug("HTTP inspection failed for %s", hostname, exc_info=True)
                    if result.status_code is not None or result.redirects:
                        return result
                    # The initial DNS snapshot is used exactly once. Fallback
                    # must validate fresh DNS, including mixed/private answers.
                    initial_dns = None
        return result

    async def _inspect_scheme(self, client: httpx.AsyncClient, hostname: str, scheme: str,
                              result: HTTPResult, initial_dns: DNSResult | None,
                              transport: httpx.AsyncBaseTransport) -> None:
        url = httpx.URL(f"{scheme}://{hostname}/")
        visited: set[str] = set()
        for hop in range(self.config.max_redirects + 1):
            url = url.copy_with(fragment=None)
            if str(url) in visited:
                raise UnsafeDestination("redirect loop detected")
            visited.add(str(url))
            # Includes redirect DNS validation, connect, TLS, headers and body.
            # This is a wall-clock deadline, not only a socket inactivity timeout.
            async with asyncio.timeout(self.config.timeout):
                validate_url(url, hostname)
                resolved = (initial_dns if initial_dns is not None and hop == 0
                            else await invoke(self.resolver.resolve, hostname))
                pinned = (pin_url(url, hostname, resolved) if self._destination_policy is None
                          else self._destination_policy(url, hostname, resolved, transport))
                result.attempts.append(str(url))
                record_destination(result, resolved, pinned)
                logger.debug("GET %s (pinned public IP %s)", url, pinned.host)
                async with client.stream(
                    "GET", pinned, headers={"Host": hostname},
                    extensions={"sni_hostname": hostname},
                ) as response:
                    record_response(response, url, result, self.evidence_headers)
                    if response.status_code in REDIRECT_CODES:
                        destination = redirect_destination(response, url, hop, self.config)
                        result.redirects.append(str(destination))
                        # Consume the end-of-message for explicitly empty bodies
                        # so httpcore can safely reuse this target's connection.
                        # Other redirect bodies are closed without downloading.
                        if response.headers.get("content-length") == "0" and "transfer-encoding" not in response.headers:
                            async for chunk in response.aiter_raw():
                                if chunk:
                                    break
                        url = destination
                        continue
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise UnsafeDestination("unexpected compressed body; analysis skipped")
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        available = self.config.max_body_bytes - len(body)
                        body.extend(chunk[:available])
                        if len(body) >= self.config.max_body_bytes:
                            result.body_truncated = True
                            break
                    result.body = body.decode("utf-8", errors="replace")
                    result.inspected_bytes = len(body)
                    result.complete = True
                    return
