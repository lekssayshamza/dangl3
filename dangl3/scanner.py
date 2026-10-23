"""Bounded worker scanning and conservative evidence-based classification."""

import asyncio
from collections.abc import Iterable
import logging
import time
from typing import cast

from dangl3.async_dns_resolver import AsyncDNSResolver
from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.async_utils import invoke
from dangl3.dns_resolver import DNSResolver
from dangl3.fingerprints import FingerprintDatabase
from dangl3.http_client import HTTPInspector
from dangl3.inputs import MAX_TARGETS, normalize_hostname
from dangl3.models import Classification, DNSResult, DNSStatus, EvidenceCategory, ScanConfig, TargetResult
from dangl3.providers import identify_providers

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, config: ScanConfig | None = None, *,
                 database: FingerprintDatabase | None = None,
                 resolver: DNSResolver | AsyncDNSResolver | None = None,
                 inspector: HTTPInspector | AsyncHTTPInspector | None = None) -> None:
        self.config = config if config is not None else ScanConfig()
        self.database = database if database is not None else FingerprintDatabase.load()
        self.resolver = resolver if resolver is not None else AsyncDNSResolver(
            self.config.timeout, self.config.max_cname_depth,
        )
        headers = {key.lower() for provider in self.database.providers
                   for rule in provider.fingerprints for key in rule.headers_all}
        self.inspector = inspector if inspector is not None else AsyncHTTPInspector(
            self.config, self.resolver, evidence_headers=headers,
        )
        self.duration_seconds = 0.0
        self._running = False

    def scan(self, hostnames: Iterable[str]) -> list[TargetResult]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.scan_async(hostnames))
        raise RuntimeError("Use await scanner.scan_async(...) inside an event loop")

    async def scan_async(self, hostnames: Iterable[str]) -> list[TargetResult]:
        # Validate the whole batch before sending any network traffic.
        if self._running:
            raise RuntimeError("A Scanner instance cannot run overlapping batches")
        targets: dict[str, str] = {}
        for original in hostnames:
            targets.setdefault(normalize_hostname(original), original.strip())
            if len(targets) > MAX_TARGETS:
                raise ValueError(f"at most {MAX_TARGETS} unique targets are supported")
        self._running = True
        started = time.perf_counter()
        results: list[TargetResult | None] = [None] * len(targets)
        pending = iter(enumerate(targets.items()))

        async def worker() -> None:
            # next() and assignment contain no await; each input is owned by one
            # worker. There is no task or queued future per target.
            for index, (hostname, original) in pending:
                results[index] = await self._run_target(hostname, original)

        try:
            if len(targets) <= 1:
                await worker()
            else:
                async with asyncio.TaskGroup() as group:
                    for index in range(min(self.config.concurrency, len(targets))):
                        group.create_task(worker(), name=f"dangl3-worker-{index}")
            return [cast(TargetResult, result) for result in results]
        finally:
            self.duration_seconds = round(time.perf_counter() - started, 6)
            self._running = False

    async def _run_target(self, hostname: str, original: str) -> TargetResult:
        result = TargetResult(hostname, DNSResult(hostname), original_hostname=original)
        started = time.perf_counter()
        try:
            await self._scan_target(result)
        except Exception as exc:
            # CancelledError is a BaseException and deliberately propagates.
            logger.exception("Unexpected scan failure for %s", hostname)
            result.classification = Classification.UNKNOWN
            result.errors.append(f"Unexpected {type(exc).__name__}: {exc}")
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "An unexpected failure prevented complete analysis.")
        finally:
            result.duration_seconds = round(time.perf_counter() - started, 6)
        result.explanation = " ".join(result.evidence)
        return result

    async def _scan_target(self, result: TargetResult) -> None:
        dns = result.dns = await invoke(self.resolver.resolve, result.hostname)
        result.errors.extend(dns.errors)
        for error in dns.errors:
            result.add_evidence(EvidenceCategory.DNS_ERROR, error)
        providers = identify_providers([result.hostname, *dns.cname_chain], self.database)
        if len(providers) > 1:
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "Ambiguous CNAME chain matches multiple providers: " +
                                ", ".join(provider.name for provider in providers))
            return
        provider = providers[0] if providers else None
        if provider:
            result.provider = provider.to_dict()
            result.limitations.append(provider.limitations)
            result.add_evidence(EvidenceCategory.DNS_PROVIDER_MATCH,
                                f"Recognized {provider.name} DNS hostname pattern.", sources=provider.sources)
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION, provider.limitations,
                                sources=provider.sources)
        if dns.status in (DNSStatus.NXDOMAIN, DNSStatus.NO_RECORDS):
            if provider and dns.cname_chain:
                result.classification = Classification.SUSPICIOUS
                result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                    "A provider CNAME chain has no terminal address records. "
                                    "This may be dangling DNS; no cloud ownership or claimability was checked.")
            elif dns.status == DNSStatus.NXDOMAIN:
                result.classification = Classification.NO_EVIDENCE
                result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                    "NXDOMAIN alone is not a takeover indicator.")
            else:
                result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                    "No address records; insufficient evidence to classify the service.")
            return
        if dns.status != DNSStatus.RESOLVED:
            result.add_evidence(EvidenceCategory.DNS_ERROR,
                                f"DNS analysis is incomplete ({dns.status.value}).")
            return
        if not provider:
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "No supported provider identified; the service is unknown.")
            return
        response = result.http = await invoke(
            self.inspector.inspect, result.hostname, http_only=provider.id == "aws_s3_website",
            initial_dns=dns,
        )
        result.errors.extend(response.errors)
        for error in response.errors:
            result.add_evidence(EvidenceCategory.HTTP_ERROR, error)
        if not response.complete:
            result.add_evidence(EvidenceCategory.HTTP_ERROR,
                                "HTTP inspection could not be completed; no fingerprint inference made.")
            return
        if response.body_truncated:
            result.warnings.append("Response body reached the inspection limit")
        matches = self.database.match(provider, response)
        result.matched_fingerprints = [match.id for match in matches]
        for match in matches:
            result.add_evidence(EvidenceCategory.HTTP_FINGERPRINT_MATCH,
                                f"Matched fingerprint {match.id}: {match.limitations}",
                                fingerprint_id=match.id, sources=match.sources)
            result.limitations.append(match.limitations)
        ambiguities = self.database.ambiguities(provider, response) + response.conflicts
        for reason in ambiguities:
            result.add_evidence(EvidenceCategory.HTTP_AMBIGUOUS, reason)
        if ambiguities:
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "Conflicting or incomplete HTTP evidence prevents a reliable resource-state inference.")
            return
        if response.dns_changed:
            result.add_evidence(EvidenceCategory.HTTP_AMBIGUOUS,
                                "DNS provider attribution changed during HTTP inspection.")
            if not matches:
                return
        if matches:
            strong = (any(match.outcome == "potential" and not match.experimental for match in matches)
                      and not response.redirects and not response.dns_changed and not response.errors)
            # A provider's own missing URL is not a dangling customer DNS record.
            has_provider_cname = bool(identify_providers(dns.cname_chain, self.database))
            result.classification = (Classification.POTENTIAL_TAKEOVER
                                     if strong and has_provider_cname else Classification.SUSPICIOUS)
            if response.redirects or response.dns_changed:
                result.add_evidence(EvidenceCategory.HTTP_AMBIGUOUS,
                                    "A redirected response or changed DNS attribution limits this match to suspicious.")
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "Resource claimability has not been verified.")
        elif not provider.fingerprints:
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "Provider identification only: no maintained HTTP fingerprint "
                                "for this provider, so resource state remains unknown.")
        elif response.body_truncated:
            result.add_evidence(EvidenceCategory.HTTP_AMBIGUOUS,
                                "Response body reached the inspection limit; analysis is incomplete.")
        elif response.status_code is not None and response.status_code >= 500:
            result.add_evidence(EvidenceCategory.HTTP_AMBIGUOUS,
                                "A server error prevents meaningful resource-state analysis.")
        else:
            result.classification = Classification.NO_EVIDENCE
            result.add_evidence(EvidenceCategory.DETECTION_LIMITATION,
                                "No maintained provider-specific indicator matched. "
                                "Generic HTTP errors are not takeover evidence; this is not proof of safety.")
