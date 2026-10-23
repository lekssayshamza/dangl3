"""Native asyncio DNS, with the same result contract as the V1 resolver."""

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.resolver

from dangl3.inputs import normalize_hostname
from dangl3.models import DNSResult, DNSStatus

logger = logging.getLogger(__name__)


class AsyncDNSResolver:
    def __init__(self, timeout: float = 5.0, max_depth: int = 10,
                 resolver: dns.asyncresolver.Resolver | None = None) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.resolver = resolver if resolver is not None else dns.asyncresolver.Resolver()

    async def resolve(self, hostname: str) -> DNSResult:
        result = DNSResult(hostname)
        current = hostname
        visited = {hostname}

        async def query(kind: str) -> tuple[list[str], DNSStatus | None]:
            logger.debug("DNS %s %s", kind, current)
            try:
                async with asyncio.timeout(self.timeout):
                    answer = await self.resolver.resolve(
                        current + ".", kind, lifetime=self.timeout, search=False,
                    )
                if kind in ("A", "AAAA") and hasattr(answer, "canonical_name"):
                    if str(answer.canonical_name).rstrip(".").lower() != current:
                        raise dns.exception.DNSException("CNAME changed during address resolution")
                values = [str(record).rstrip(".").lower() for record in answer]
                result.records.setdefault(current, {})[kind] = values
                return values, None
            except dns.resolver.NoAnswer:
                result.records.setdefault(current, {})[kind] = []
                return [], None
            except dns.resolver.NXDOMAIN:
                state = DNSStatus.NXDOMAIN
            except (dns.exception.Timeout, TimeoutError):
                state = DNSStatus.TIMEOUT
            except dns.exception.DNSException as exc:
                result.errors.append(f"{current} {kind}: {type(exc).__name__}: {exc}")
                return [], DNSStatus.ERROR
            result.errors.append(f"{current} {kind}: {state.value}")
            return [], state

        while True:
            cnames, error = await query("CNAME")
            if error:
                result.status = error
                return result
            if not cnames:
                break
            if len(cnames) != 1:
                result.status = DNSStatus.ERROR
                result.errors.append(f"{current}: multiple CNAME targets")
                return result
            try:
                target = normalize_hostname(cnames[0])
            except ValueError as exc:
                result.status = DNSStatus.ERROR
                result.errors.append(f"Invalid CNAME target: {exc}")
                return result
            if len(result.cname_chain) >= self.max_depth:
                result.status = DNSStatus.MAX_DEPTH
                result.errors.append("CNAME depth limit reached; see records for the next hop")
                return result
            result.cname_chain.append(target)
            if target in visited:
                result.status = DNSStatus.LOOP
                result.errors.append(f"CNAME loop at {target}")
                return result
            visited.add(target)
            current = target

        # Sequential within a target: the worker limit also bounds DNS operations.
        result.a, error_a = await query("A")
        result.aaaa, error_aaaa = await query("AAAA")
        errors = [state for state in (error_a, error_aaaa) if state]
        if result.a or result.aaaa:
            result.status = DNSStatus.PARTIAL if errors else DNSStatus.RESOLVED
        elif errors:
            result.status = errors[0]
        return result
