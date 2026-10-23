"""Bounded CNAME traversal, followed by terminal A and AAAA queries."""

import logging

import dns.exception
import dns.resolver

from dangl3.inputs import normalize_hostname
from dangl3.models import DNSResult, DNSStatus

logger = logging.getLogger(__name__)


class DNSResolver:
    def __init__(self, timeout: float = 5.0, max_depth: int = 10,
                 resolver: dns.resolver.Resolver | None = None) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.resolver = resolver if resolver is not None else dns.resolver.Resolver()

    def _query(self, hostname: str, record_type: str) -> list[str]:
        logger.debug("DNS %s %s", record_type, hostname)
        answer = self.resolver.resolve(
            hostname + ".", record_type, lifetime=self.timeout, search=False,
        )
        if record_type in ("A", "AAAA") and hasattr(answer, "canonical_name"):
            if str(answer.canonical_name).rstrip(".").lower() != hostname:
                raise dns.exception.DNSException("CNAME changed during address resolution")
        return [str(record).rstrip(".").lower() for record in answer]

    def resolve(self, hostname: str) -> DNSResult:
        result = DNSResult(hostname)
        current = hostname
        visited = {hostname}

        def query(kind: str) -> tuple[list[str], DNSStatus | None]:
            try:
                values = self._query(current, kind)
                result.records.setdefault(current, {})[kind] = values
                return values, None
            except dns.resolver.NoAnswer:
                result.records.setdefault(current, {})[kind] = []
                return [], None
            except dns.resolver.NXDOMAIN:
                state = DNSStatus.NXDOMAIN
            except dns.exception.Timeout:
                state = DNSStatus.TIMEOUT
            except dns.exception.DNSException as exc:
                result.errors.append(f"{current} {kind}: {type(exc).__name__}: {exc}")
                return [], DNSStatus.ERROR
            result.errors.append(f"{current} {kind}: {state.value}")
            return [], state

        while True:
            cnames, error = query("CNAME")
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

        result.a, error_a = query("A")
        result.aaaa, error_aaaa = query("AAAA")
        errors = [state for state in (error_a, error_aaaa) if state]
        if result.a or result.aaaa:
            result.status = DNSStatus.PARTIAL if errors else DNSStatus.RESOLVED
        elif errors:
            result.status = errors[0]
        return result
