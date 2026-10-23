"""Run with python -m integration_lab.runner; no cloud or root access."""

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass

import dns.asyncresolver
from rich.console import Console
from rich.table import Table

from dangl3.async_dns_resolver import AsyncDNSResolver
from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.models import DNSStatus, ScanConfig, TargetResult
from dangl3.scanner import Scanner
from integration_lab.dns_server import DNSServer
from integration_lab.http_server import HTTPServer, ResponseGate
from integration_lab.scenarios import BY_HOST, SCENARIOS
from integration_lab.transport import LabScope


@dataclass(frozen=True)
class ScenarioCheck:
    scenario: str
    classification: str
    passed: bool
    problems: tuple[str, ...] = ()


class LocalLab:
    def __init__(self, concurrency: int = 3, *, hold_responses: bool = False) -> None:
        self.config = ScanConfig(timeout=5.0, concurrency=concurrency, max_body_bytes=1024, max_redirects=2)
        hosts = tuple(s.hostname for s in SCENARIOS if s.fixture)[:concurrency]
        self.gate = ResponseGate(hosts, hold=hold_responses)
        self.dns = DNSServer()
        self.http = HTTPServer(self.dns, self.gate)
        self.stack = AsyncExitStack()
        self.scope: LabScope | None = None
        self.scanner: Scanner | None = None
        self.closed = False

    async def __aenter__(self) -> "LocalLab":
        await self.stack.__aenter__()
        try:
            await self.stack.enter_async_context(self.dns)
            await self.stack.enter_async_context(self.http)
            self.scope = LabScope(self.http.endpoints)
            self.stack.push_async_callback(self.scope.aclose)
            native = dns.asyncresolver.Resolver(configure=False)
            native.nameservers = ["127.0.0.1"]
            native.port = self.dns.address[1]
            native.cache = None
            native.search = []
            native.timeout = self.config.timeout
            native.lifetime = self.config.timeout
            self.resolver = AsyncDNSResolver(self.config.timeout, self.config.max_cname_depth, native)
            inspector = AsyncHTTPInspector(
                self.config, self.resolver, transport_factory=self.scope.transport_factory,
                _destination_policy=self.scope.pin,
            )
            self.scanner = Scanner(self.config, resolver=self.resolver, inspector=inspector)
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def __aexit__(self, *args: object) -> None:
        try:
            await self.stack.__aexit__(*args)
        finally:
            self.closed = True

    async def scan(self) -> list[TargetResult]:
        if self.scanner is None or self.closed:
            raise RuntimeError("lab must be entered before scanning")
        # Include a duplicate to verify production normalization/deduplication.
        targets = [s.hostname for s in SCENARIOS] + [SCENARIOS[0].hostname.upper() + "."]
        return await self.scanner.scan_async(targets)

    def check_results(self, results: list[TargetResult]) -> list[ScenarioCheck]:
        by_host = {result.hostname: result for result in results}
        checks = []
        for scenario in SCENARIOS:
            result = by_host.get(scenario.hostname)
            problems = []
            if result is None:
                checks.append(ScenarioCheck(scenario.id, "MISSING", False, ("target result missing",)))
                continue
            if result.classification != scenario.expected:
                problems.append(f"expected {scenario.expected.value}")
            requests = [request for request in self.http.requests if request.hostname == scenario.hostname]
            if len(requests) != (1 if scenario.fixture else 0):
                problems.append("unexpected HTTP request count")
            if scenario.blocked and (result.http is None or result.http.complete or not result.http.errors):
                problems.append("unsafe destination was not reported as blocked/incomplete")
            if scenario.id == "body-limit" and (not result.http or not result.http.body_truncated):
                problems.append("body cap was not exercised")
            if scenario.id == "incomplete-http" and (not result.http or result.http.complete or not result.http.errors):
                problems.append("incomplete HTTP framing was not detected")
            if scenario.id == "nxdomain" and result.dns.status != DNSStatus.NXDOMAIN:
                problems.append("NXDOMAIN was not exercised")
            if scenario.id == "cname-loop" and result.dns.status != DNSStatus.LOOP:
                problems.append("CNAME loop was not exercised")
            checks.append(ScenarioCheck(scenario.id, result.classification.value, not problems, tuple(problems)))
        return checks

    def invariants(self, results: list[TargetResult]) -> dict[str, bool]:
        rebound_target = BY_HOST["dns-rebinding.dangl3.test"].target
        addresses = [q.addresses for q in self.dns.queries if q.name == rebound_target and q.record_type == "A"]
        wave = self.gate.hosts
        response_wave = [host for host in self.http.response_order if host in wave]
        return {
            "stable input order and deduplication": [r.hostname for r in results] == [s.hostname for s in SCENARIOS],
            "bounded simultaneous HTTP requests": self.http.peak_requests == min(
                self.config.concurrency, sum(s.fixture is not None for s in SCENARIOS)),
            "responses deliberately reordered": len(wave) == 1 or bool(response_wave and response_wave[0] != wave[0]),
            "real DNS rebinding observed": addresses == [("127.0.0.1",), ("169.254.169.254",)],
            "only assigned loopback HTTP endpoints": bool(self.scope.requests) and all(
                request.endpoint == self.http.endpoints[request.scheme] for request in self.scope.requests),
            "real HTTPS served": {request.hostname for request in self.http.requests if request.tls}
                                    == {"missing-vercel.dangl3.test", "github-dns-only.dangl3.test"},
            "per-target transport cleanup": all(transport.closed for transport in self.scope.transports),
            "no server errors": not self.dns.errors and not self.http.errors,
        }

    def cleanup_ok(self) -> bool:
        return bool(self.closed and self.dns.closed.is_set() and self.http.closed
                    and not self.http.tasks and not self.http.writers and not self.http.active_requests
                    and self.scope is not None and not self.scope.active
                    and all(transport.closed for transport in self.scope.transports))


async def run() -> bool:
    console = Console(markup=False, highlight=False)
    lab = LocalLab()
    async with lab:
        console.print("Dangl3 local integration lab — synthetic findings only")
        console.print(f"DNS: {lab.dns.address}; HTTP/HTTPS: {lab.http.endpoints}")
        results = await lab.scan()
        checks = lab.check_results(results)
        invariants = lab.invariants(results)
    invariants["servers/tasks/connections closed"] = lab.cleanup_ok()
    invariants["no shutdown errors"] = not lab.dns.errors and not lab.http.errors
    table = Table("Scenario", "Actual classification", "Result")
    for check in checks:
        table.add_row(check.scenario, check.classification, "PASS" if check.passed else "FAIL")
        for problem in check.problems:
            console.print(f"{check.scenario}: {problem}")
    console.print(table)
    for name, passed in invariants.items():
        console.print(f"{'PASS' if passed else 'FAIL'}: {name}")
    passed = all(check.passed for check in checks) and all(invariants.values())
    console.print(f"{sum(check.passed for check in checks)}/{len(checks)} scenarios passed; "
                  f"peak concurrent HTTP requests: {lab.http.peak_requests}/{lab.config.concurrency}")
    return passed


def main() -> int:
    try:
        return 0 if asyncio.run(run()) else 1
    except KeyboardInterrupt:
        Console(stderr=True).print("Local lab cancelled; server cleanup requested.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
