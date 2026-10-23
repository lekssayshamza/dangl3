import asyncio
from unittest.mock import AsyncMock

import dns.exception
import dns.name
import dns.resolver
import pytest

from dangl3.async_dns_resolver import AsyncDNSResolver
from dangl3.models import DNSStatus


def backend(records):
    async def query(hostname, kind, **kwargs):
        assert hostname.endswith(".") and kwargs["search"] is False
        value = records.get((hostname.rstrip("."), kind), dns.resolver.NoAnswer())
        if isinstance(value, Exception):
            raise value
        return value
    result = AsyncMock()
    result.resolve.side_effect = query
    return result


def test_async_cname_chain_addresses_and_records():
    resolver = AsyncDNSResolver(resolver=backend({
        ("blog.example.com", "CNAME"): ["alias.example.com."],
        ("alias.example.com", "CNAME"): ["owner.github.io."],
        ("owner.github.io", "A"): ["93.184.216.34"],
        ("owner.github.io", "AAAA"): ["2606:4700:4700::1111"],
    }))
    result = asyncio.run(resolver.resolve("blog.example.com"))
    assert result.status == DNSStatus.RESOLVED
    assert result.cname_chain == ["alias.example.com", "owner.github.io"]
    assert result.records["owner.github.io"]["AAAA"] == result.aaaa


@pytest.mark.parametrize("error, status", [
    (dns.resolver.NXDOMAIN(), DNSStatus.NXDOMAIN),
    (dns.exception.Timeout(), DNSStatus.TIMEOUT),
    (dns.resolver.NoNameservers(), DNSStatus.ERROR),
])
def test_async_dns_failures_are_structured(error, status):
    resolver = AsyncDNSResolver(resolver=backend({("blog.example.com", "CNAME"): error}))
    result = asyncio.run(resolver.resolve("blog.example.com"))
    assert result.status == status and result.errors


def test_async_dns_loop_and_depth():
    records = {("a.example.com", "CNAME"): ["b.example.com"],
               ("b.example.com", "CNAME"): ["a.example.com"]}
    assert asyncio.run(AsyncDNSResolver(resolver=backend(records)).resolve("a.example.com")).status == DNSStatus.LOOP
    assert asyncio.run(AsyncDNSResolver(max_depth=1, resolver=backend(records)).resolve("a.example.com")).status == DNSStatus.MAX_DEPTH


def test_async_dns_partial_address_failure():
    resolver = AsyncDNSResolver(resolver=backend({
        ("blog.example.com", "A"): ["93.184.216.34"],
        ("blog.example.com", "AAAA"): dns.exception.Timeout(),
    }))
    assert asyncio.run(resolver.resolve("blog.example.com")).status == DNSStatus.PARTIAL


def test_async_dns_canonical_change_is_rejected():
    class Answer(list):
        canonical_name = dns.name.from_text("changed.example.net.")
    resolver = AsyncDNSResolver(resolver=backend({("blog.example.com", "A"): Answer(["93.184.216.34"])}))
    result = asyncio.run(resolver.resolve("blog.example.com"))
    assert result.status == DNSStatus.ERROR
    assert "CNAME changed" in result.errors[0]


def test_async_dns_deadline_and_event_loop_progress():
    async def scenario():
        ticks = 0
        async def query(*args, **kwargs):
            await asyncio.sleep(100)
        async def ticker():
            nonlocal ticks
            for _ in range(3):
                await asyncio.sleep(0)
                ticks += 1
        native = AsyncMock()
        native.resolve.side_effect = query
        resolver = AsyncDNSResolver(timeout=0.02, resolver=native)
        task = asyncio.create_task(ticker())
        result = await resolver.resolve("blog.example.com")
        await task
        assert result.status == DNSStatus.TIMEOUT
        assert ticks == 3
    asyncio.run(scenario())


def test_dns_cancellation_propagates():
    async def scenario():
        entered = asyncio.Event()
        async def query(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        native = AsyncMock()
        native.resolve.side_effect = query
        task = asyncio.create_task(AsyncDNSResolver(resolver=native).resolve("blog.example.com"))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(scenario())
