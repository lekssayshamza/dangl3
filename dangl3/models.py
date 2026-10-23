"""Serializable scan data; response bodies stay in memory only."""

from dataclasses import asdict, dataclass, field
from enum import Enum
import math


class Classification(str, Enum):
    POTENTIAL_TAKEOVER = "POTENTIAL_TAKEOVER"
    SUSPICIOUS = "SUSPICIOUS"
    NO_EVIDENCE = "NO_EVIDENCE"
    UNKNOWN = "UNKNOWN"


class EvidenceCategory(str, Enum):
    DNS_PROVIDER_MATCH = "DNS_PROVIDER_MATCH"
    HTTP_FINGERPRINT_MATCH = "HTTP_FINGERPRINT_MATCH"
    HTTP_AMBIGUOUS = "HTTP_AMBIGUOUS"
    DNS_ERROR = "DNS_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    DETECTION_LIMITATION = "DETECTION_LIMITATION"


@dataclass(frozen=True)
class Evidence:
    category: EvidenceCategory
    message: str
    fingerprint_id: str | None = None
    sources: tuple[str, ...] = ()


class DNSStatus(str, Enum):
    RESOLVED = "RESOLVED"
    NXDOMAIN = "NXDOMAIN"
    NO_RECORDS = "NO_RECORDS"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    LOOP = "LOOP"
    MAX_DEPTH = "MAX_DEPTH"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True)
class ScanConfig:
    timeout: float = 5.0
    max_cname_depth: int = 10
    max_redirects: int = 3
    max_body_bytes: int = 65536
    concurrency: int = 5

    def __post_init__(self) -> None:
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 20:
            raise ValueError("concurrency must be an integer between 1 and 20")
        if type(self.timeout) not in (int, float) or not math.isfinite(self.timeout) or not 0 < self.timeout <= 120:
            raise ValueError("timeout must be finite and between 0 (exclusive) and 120 seconds")
        if type(self.max_cname_depth) is not int or not 1 <= self.max_cname_depth <= 50:
            raise ValueError("max_cname_depth must be between 1 and 50")
        if type(self.max_redirects) is not int or not 0 <= self.max_redirects <= 10:
            raise ValueError("max_redirects must be between 0 and 10")
        if type(self.max_body_bytes) is not int or not 1 <= self.max_body_bytes <= 1048576:
            raise ValueError("max_body_bytes must be between 1 and 1048576")


@dataclass
class DNSResult:
    hostname: str
    status: DNSStatus = DNSStatus.NO_RECORDS
    cname_chain: list[str] = field(default_factory=list)
    records: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def terminal_hostname(self) -> str:
        return self.cname_chain[-1] if self.cname_chain else self.hostname


@dataclass
class HTTPResult:
    final_url: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = field(default="", repr=False)
    body_truncated: bool = False
    complete: bool = False
    redirects: list[str] = field(default_factory=list)
    attempts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    connected_addresses: list[str] = field(default_factory=list)
    dns_changed: bool = False
    conflicts: list[str] = field(default_factory=list)
    inspected_bytes: int = 0
    dns_chains: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = asdict(self)
        del result["body"]
        return result


@dataclass
class TargetResult:
    hostname: str
    dns: DNSResult
    provider: dict | None = None
    http: HTTPResult | None = None
    classification: Classification = Classification.UNKNOWN
    matched_fingerprints: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    original_hostname: str | None = None
    structured_evidence: list[Evidence] = field(default_factory=list)
    explanation: str = ""
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def add_evidence(self, category: EvidenceCategory, message: str, *,
                     fingerprint_id: str | None = None, sources: tuple[str, ...] = ()) -> None:
        self.evidence.append(message)
        self.structured_evidence.append(Evidence(category, message, fingerprint_id, sources))

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "dns": asdict(self.dns),
            "provider": self.provider,
            "http": self.http.to_dict() if self.http else None,
            "classification": self.classification.value,
            "matched_fingerprints": self.matched_fingerprints,
            "evidence": self.evidence,
            "errors": self.errors,
            "original_hostname": self.original_hostname or self.hostname,
            "structured_evidence": [asdict(item) for item in self.structured_evidence],
            "explanation": self.explanation,
            "limitations": self.limitations,
            "warnings": self.warnings,
            "duration_seconds": self.duration_seconds,
        }
