"""Shared destination policy for synchronous and asynchronous transports."""

import ipaddress

import httpx

from dangl3.inputs import normalize_hostname
from dangl3.models import DNSResult, DNSStatus


class UnsafeDestination(ValueError):
    """A destination did not satisfy the HTTP scan policy."""


# Conservatively block special-use allocations even on older Python versions
# whose ipaddress tables classify some of these as global. False negatives are
# preferable to contacting a platform service or transition gateway.
BLOCKED_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
))
BLOCKED_V6 = tuple(ipaddress.ip_network(value) for value in (
    "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
    "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
    "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
))


def is_public_address(value: str) -> bool:
    if "%" in value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    blocked = BLOCKED_V4 if address.version == 4 else BLOCKED_V6
    return (address.is_global and not address.is_multicast and not address.is_reserved
            and not address.is_unspecified and not any(address in network for network in blocked))


def validate_url(url: httpx.URL, hostname: str) -> None:
    if url.scheme not in ("https", "http") or url.username or url.password or not url.host:
        raise UnsafeDestination("unsupported URL scheme or credentials")
    if normalize_hostname(url.host) != hostname:
        raise UnsafeDestination("redirect to another hostname blocked")
    if url.port not in (80 if url.scheme == "http" else 443, None):
        raise UnsafeDestination("nonstandard destination port blocked")


def pin_url(url: httpx.URL, hostname: str, resolved: DNSResult) -> httpx.URL:
    validate_url(url, hostname)
    addresses = resolved.a + resolved.aaaa
    if resolved.hostname != hostname or resolved.status != DNSStatus.RESOLVED or not addresses:
        raise UnsafeDestination("destination DNS could not be fully validated")
    if not all(is_public_address(address) for address in addresses):
        raise UnsafeDestination("private, internal, or special-use destination blocked")
    for family, values in ((4, resolved.a), (6, resolved.aaaa)):
        if any(ipaddress.ip_address(value).version != family for value in values):
            raise UnsafeDestination("DNS address family mismatch")
    return url.copy_with(host=addresses[0])
