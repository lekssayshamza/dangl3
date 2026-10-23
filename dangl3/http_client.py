"""Low-volume HTTP inspection with same-host redirects and pinned public IPs."""

import logging
import time

import httpx

from dangl3 import __version__
from dangl3.dns_resolver import DNSResolver
from dangl3.models import DNSResult, HTTPResult, ScanConfig
from dangl3.network_safety import UnsafeDestination, is_public_address, pin_url, validate_url

logger = logging.getLogger(__name__)
REDIRECT_CODES = {301, 302, 303, 307, 308}
# Keep evidence headers only. Never store cookies, authorization, or full response bodies.
EVIDENCE_HEADERS = {"server", "content-type", "x-vercel-error", "x-powered-by", "x-cache"}
USER_AGENT = f"Dangl3/{__version__} (+authorized-security-scanning)"


def record_destination(result: HTTPResult, dns: DNSResult, pinned: httpx.URL) -> None:
    chain = list(dns.cname_chain)
    if result.dns_chains and chain != result.dns_chains[0]:
        result.dns_changed = True
    result.dns_chains.append(chain)
    result.connected_addresses.append(pinned.host)


def record_response(response: httpx.Response, url: httpx.URL, result: HTTPResult,
                    evidence_headers: set[str]) -> None:
    result.final_url = str(url)
    result.status_code = response.status_code
    result.headers = {key.lower(): value[:1024] for key, value in response.headers.items()
                      if key.lower() in evidence_headers}
    for key in evidence_headers:
        if len(response.headers.get_list(key)) > 1:
            result.conflicts.append(f"Duplicate evidence header: {key}")


def redirect_destination(response: httpx.Response, url: httpx.URL, hop: int,
                         config: ScanConfig) -> httpx.URL:
    locations = response.headers.get_list("location")
    if len(locations) != 1 or not locations[0]:
        raise UnsafeDestination("redirect has missing or duplicate Location headers")
    location = locations[0]
    if len(location) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in location):
        raise UnsafeDestination("invalid or oversized redirect Location")
    if hop == config.max_redirects:
        raise UnsafeDestination("redirect limit reached")
    destination = url.join(location)
    if url.scheme == "https" and destination.scheme == "http":
        raise UnsafeDestination("HTTPS downgrade redirect blocked")
    return destination


class HTTPInspector:
    def __init__(self, config: ScanConfig, resolver: DNSResolver,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.config = config
        self.resolver = resolver
        self.transport = transport

    def _pin(self, url: httpx.URL, original_hostname: str) -> httpx.URL:
        validate_url(url, original_hostname)
        resolved = self.resolver.resolve(original_hostname)
        # httpx connects to this literal IP; it never re-resolves the hostname.
        # Host and TLS SNI retain the authorized hostname, including certificate checks.
        return pin_url(url, original_hostname, resolved)

    def inspect(self, hostname: str, *, http_only: bool = False,
                initial_dns: DNSResult | None = None) -> HTTPResult:
        result = HTTPResult()
        schemes = ("http",) if http_only else ("https", "http")
        # Disable environment proxies/netrc and automatic redirects. TLS stays verified.
        with httpx.Client(
            timeout=self.config.timeout, follow_redirects=False, trust_env=False,
            transport=self.transport, headers={
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "identity",
            },
        ) as client:
            for scheme in schemes:
                url = httpx.URL(f"{scheme}://{hostname}/")
                try:
                    self._inspect_url(client, url, hostname, result, initial_dns=initial_dns)
                    initial_dns = None
                    return result
                except UnsafeDestination as exc:
                    result.errors.append(f"HTTP destination blocked: {exc}")
                    return result
                except (httpx.HTTPError, ValueError) as exc:
                    initial_dns = None
                    result.errors.append(f"{scheme.upper()}: {type(exc).__name__}: {exc}")
                    logger.debug("HTTP inspection failed for %s", url, exc_info=True)
                    # Only fall back before any response, never after redirects/body failures.
                    if result.status_code is not None or result.redirects:
                        return result
        return result

    def _inspect_url(self, client: httpx.Client, url: httpx.URL,
                     hostname: str, result: HTTPResult, *, initial_dns: DNSResult | None = None) -> None:
        visited: set[str] = set()
        deadline = time.monotonic() + self.config.timeout
        for hop in range(self.config.max_redirects + 1):
            url = url.copy_with(fragment=None)
            if str(url) in visited:
                raise UnsafeDestination("redirect loop detected")
            visited.add(str(url))
            validate_url(url, hostname)
            resolved = initial_dns if initial_dns is not None and hop == 0 else self.resolver.resolve(hostname)
            pinned = pin_url(url, hostname, resolved)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.ReadTimeout("HTTP inspection deadline exceeded")
            result.attempts.append(str(url))
            record_destination(result, resolved, pinned)
            logger.debug("GET %s (pinned public IP %s)", url, pinned.host)
            with client.stream(
                "GET", pinned, headers={"Host": hostname},
                extensions={"sni_hostname": hostname}, timeout=remaining,
            ) as response:
                record_response(response, url, result, EVIDENCE_HEADERS)
                if response.status_code in REDIRECT_CODES:
                    destination = redirect_destination(response, url, hop, self.config)
                    result.redirects.append(str(destination))
                    if response.headers.get("content-length") == "0" and "transfer-encoding" not in response.headers:
                        for chunk in response.iter_raw():
                            if chunk:
                                break
                    url = destination
                    continue
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise UnsafeDestination("unexpected compressed body; analysis skipped")
                body = bytearray()
                # Read raw bytes to avoid decompression bombs. Close at the byte cap.
                # Do not accumulate fixed-size chunks inside httpx: a slow peer
                # could otherwise trickle bytes indefinitely before our deadline
                # check runs. httpcore bounds each raw socket read internally.
                for chunk in response.iter_raw():
                    if time.monotonic() > deadline:
                        raise httpx.ReadTimeout("HTTP inspection deadline exceeded")
                    available = self.config.max_body_bytes - len(body)
                    body.extend(chunk[:available])
                    if len(body) >= self.config.max_body_bytes:
                        result.body_truncated = True
                        break
                result.body = body.decode("utf-8", errors="replace")
                result.inspected_bytes = len(body)
                result.complete = True
                return
