import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.models import DNSResult, DNSStatus, HTTPResult, ScanConfig
from dangl3.scanner import Scanner


@pytest.mark.parametrize("concurrency", [1, 5, 20])
def test_fixed_workers_maximum_concurrency_and_stable_order(concurrency):
    async def scenario():
        active = peak = 0
        worker_counts = []
        async def resolve(hostname):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            worker_counts.append(sum(task.get_name().startswith("dangl3-worker-") for task in asyncio.all_tasks()))
            await asyncio.sleep(0.002)
            active -= 1
            return DNSResult(hostname, DNSStatus.NXDOMAIN)
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        scanner = Scanner(ScanConfig(concurrency=concurrency), resolver=resolver)
        targets = [f"host{i}.example.com" for i in range(61)]
        results = await scanner.scan_async(targets)
        assert [result.hostname for result in results] == targets
        assert peak == concurrency
        assert max(worker_counts) == concurrency
        assert active == 0
        assert scanner.duration_seconds > 0
        assert all(result.duration_seconds >= 0 for result in results)
    asyncio.run(scenario())


def test_out_of_order_completion_preserves_input_order_and_original():
    async def scenario():
        completed = []
        async def resolve(hostname):
            if hostname.startswith("slow"):
                await asyncio.sleep(0.02)
            completed.append(hostname)
            return DNSResult(hostname, DNSStatus.NXDOMAIN)
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        results = await Scanner(resolver=resolver).scan_async(["Slow.Example.com.", "fast.example.com", "slow.example.com"])
        assert completed[0] == "fast.example.com"
        assert [r.hostname for r in results] == ["slow.example.com", "fast.example.com"]
        assert results[0].original_hostname == "Slow.Example.com."
    asyncio.run(scenario())


def test_one_target_has_no_worker_task_overhead():
    async def scenario():
        async def resolve(hostname):
            assert not any(t.get_name().startswith("dangl3-worker-") for t in asyncio.all_tasks())
            return DNSResult(hostname, DNSStatus.NXDOMAIN)
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        assert len(await Scanner(resolver=resolver).scan_async(["one.example.com"])) == 1
    asyncio.run(scenario())


def test_individual_async_failure_does_not_cancel_batch():
    async def scenario():
        async def resolve(hostname):
            if hostname == "broken.example.com":
                raise RuntimeError("fixture failure")
            return DNSResult(hostname, DNSStatus.NXDOMAIN)
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        results = await Scanner(resolver=resolver).scan_async(["broken.example.com", "healthy.example.com"])
        assert results[0].classification.value == "UNKNOWN"
        assert results[0].errors
        assert results[1].classification.value == "NO_EVIDENCE"
    asyncio.run(scenario())


def test_cancellation_awaits_workers_streams_and_transports():
    async def scenario():
        entered = asyncio.Event()
        state = {"active": 0, "stream_closed": 0, "transport_closed": 0}
        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                state["active"] += 1
                if state["active"] == 3:
                    entered.set()
                await asyncio.Event().wait()
                yield b"unreachable"
            async def aclose(self):
                state["stream_closed"] += 1
                state["active"] -= 1
        class Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                return httpx.Response(200, stream=Stream())
            async def aclose(self):
                state["transport_closed"] += 1
        async def resolve(hostname):
            return DNSResult(hostname, DNSStatus.RESOLVED, cname_chain=["owner.github.io"], a=["93.184.216.34"])
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        config = ScanConfig(concurrency=3)
        scanner = Scanner(config, resolver=resolver, inspector=AsyncHTTPInspector(config, resolver, transport_factory=Transport))
        task = asyncio.create_task(scanner.scan_async([f"host{i}.example.com" for i in range(100)]))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state == {"active": 0, "stream_closed": 3, "transport_closed": 3}
        assert not scanner._running
        assert not any(t.get_name().startswith("dangl3-worker-") for t in asyncio.all_tasks())
    asyncio.run(scenario())


def test_sync_injected_dns_does_not_block_event_loop():
    import threading
    async def scenario():
        entered, release = threading.Event(), threading.Event()
        class Resolver:
            def resolve(self, hostname):
                entered.set()
                assert release.wait(timeout=1)
                return DNSResult(hostname, DNSStatus.NXDOMAIN)
        scanner = Scanner(resolver=Resolver())
        task = asyncio.create_task(scanner.scan_async(["one.example.com"]))
        for _ in range(100):
            await asyncio.sleep(0.001)
            if entered.is_set():
                break
        release.set()
        assert entered.is_set()
        assert len(await task) == 1
    asyncio.run(scenario())


def test_overlapping_batches_rejected_and_sync_api_guidance():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def resolve(hostname):
            entered.set()
            await release.wait()
            return DNSResult(hostname, DNSStatus.NXDOMAIN)
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        scanner = Scanner(resolver=resolver)
        task = asyncio.create_task(scanner.scan_async(["one.example.com"]))
        await entered.wait()
        with pytest.raises(RuntimeError, match="overlapping"):
            await scanner.scan_async(["two.example.com"])
        with pytest.raises(RuntimeError, match="scan_async"):
            scanner.scan(["two.example.com"])
        release.set()
        await task
    asyncio.run(scenario())


@pytest.mark.parametrize("concurrency", [1, 5, 20])
def test_actual_http_operation_concurrency_is_bounded(concurrency):
    async def scenario():
        active = peak = 0
        async def handler(request):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.003)
                return httpx.Response(200, stream=httpx.ByteStream(b"healthy"))
            finally:
                active -= 1
        async def resolve(hostname):
            return DNSResult(hostname, DNSStatus.RESOLVED, cname_chain=["project.vercel.app"], a=["93.184.216.34"])
        resolver = AsyncMock()
        resolver.resolve.side_effect = resolve
        config = ScanConfig(concurrency=concurrency)
        inspector = AsyncHTTPInspector(config, resolver, transport_factory=lambda: httpx.MockTransport(handler))
        results = await Scanner(config, resolver=resolver, inspector=inspector).scan_async(
            [f"host{i}.example.com" for i in range(41)])
        assert len(results) == 41
        assert peak == concurrency and active == 0
        assert resolver.resolve.call_count == 41  # No duplicate first-request DNS.
    asyncio.run(scenario())


def test_target_limit_rejects_batch_before_network():
    resolver = AsyncMock()
    scanner = Scanner(resolver=resolver)
    with pytest.raises(ValueError, match="10000"):
        scanner.scan(f"host{i}.example.com" for i in range(10001))
    resolver.resolve.assert_not_called()
