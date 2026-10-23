"""Load a deliberately small JSON rule language; no executable expressions."""

from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser
from importlib.resources import files
import json
import logging
from pathlib import Path
import re
from urllib.parse import urlsplit

from dangl3.inputs import normalize_hostname
from dangl3.models import HTTPResult

logger = logging.getLogger(__name__)
MAX_DATABASE_BYTES = 1024 * 1024
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z", re.ASCII)
WORD_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)


def _contains(body: str, literal: str) -> bool:
    # Use literal search, not a generated regex. This bounds error-code tokens
    # without making long, repeated user-supplied literals expensive regexes.
    if not literal:
        return False
    if not all(character in WORD_CHARACTERS for character in literal):
        return literal in body
    start = body.find(literal)
    while start >= 0:
        end = start + len(literal)
        if ((start == 0 or body[start - 1] not in WORD_CHARACTERS)
                and (end == len(body) or body[end] not in WORD_CHARACTERS)):
            return True
        # Overlapping occurrences start inside this word, so cannot have a
        # valid left boundary. Skip them without scanning every character.
        start = body.find(literal, end)
    return False


class FingerprintDatabaseError(ValueError):
    """The fingerprint database cannot be used."""


@dataclass(frozen=True)
class Fingerprint:
    id: str
    status_codes: tuple[int, ...]
    body_all: tuple[str, ...]
    headers_all: dict[str, str]
    negative_body: tuple[str, ...]
    experimental: bool
    outcome: str
    sources: tuple[str, ...]
    limitations: str
    body_title: str | None = None

    def body_matches(self, body: str) -> bool:
        if not all(_contains(body, text) for text in self.body_all):
            return False
        if self.body_title is not None:
            parser = _TitleParser()
            parser.feed(body)
            return " ".join("".join(parser.parts).split()) == self.body_title
        return True

    def matches(self, response: HTTPResult) -> bool:
        if not response.complete or response.body_truncated or response.status_code not in self.status_codes:
            return False
        # Negative indicators cannot be reliably excluded from a truncated body.
        if response.body_truncated and self.negative_body:
            return False
        headers = {key.lower(): value for key, value in response.headers.items()}
        return (
            self.body_matches(response.body)
            and all(headers.get(key.lower(), "").casefold() == value.casefold()
                    for key, value in self.headers_all.items())
            and not any(_contains(response.body, text) for text in self.negative_body)
        )


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    dns_suffixes: tuple[str, ...]
    fingerprints: tuple[Fingerprint, ...]
    limitations: str
    sources: tuple[str, ...]
    dns_exact: tuple[str, ...] = ()
    last_reviewed: str | None = None
    review_basis: str = "documentation"

    @property
    def http_coverage(self) -> str:
        if not self.fingerprints:
            return "dns_only"
        return "limited" if all(rule.experimental for rule in self.fingerprints) else "yes"

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "limitations": self.limitations,
                "sources": list(self.sources), "dns_detection": True,
                "dns_patterns": ([{"type": "suffix", "value": suffix} for suffix in self.dns_suffixes]
                                 + [{"type": "exact", "value": name} for name in self.dns_exact]),
                "fingerprint_available": bool(self.fingerprints),
                "http_fingerprint": self.http_coverage,
                "fingerprint_ids": [rule.id for rule in self.fingerprints],
                "capabilities": ["dns_identification"] + (["http_indicators"] if self.fingerprints else []),
                "last_reviewed": self.last_reviewed, "review_basis": self.review_basis,
                "live_verified_on": None, "claimability_verified": False}


def _strings(value: object, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 128 or not all(
        isinstance(x, str) and x.strip() and len(x) <= 4096 for x in value
    ):
        raise ValueError("expected a list of nonempty strings")
    if nonempty and not value:
        raise ValueError("list must not be empty")
    return tuple(value)


def _text(value: object) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("expected nonempty text")
    return value


def _sources(value: object) -> tuple[str, ...]:
    sources = _strings(value, nonempty=True)
    for url in sources:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("sources must be absolute HTTPS URLs without credentials")
        if any(ord(c) < 32 or ord(c) == 127 for c in url) or parsed.port not in (None, 443):
            raise ValueError("invalid source URL characters or port")
    return sources


def _fingerprint(raw: dict) -> Fingerprint:
    allowed = {"id", "status_codes", "body_all", "headers_all", "negative_body", "experimental",
               "outcome", "sources", "limitations", "body_title"}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise ValueError("unknown fingerprint field or invalid rule object")
    codes = raw["status_codes"]
    if not isinstance(codes, list) or not codes or len(codes) > 32 or not all(
        type(x) is int and 100 <= x <= 599 for x in codes
    ):
        raise ValueError("invalid HTTP status codes")
    body = _strings(raw["body_all"], nonempty=True)
    headers = raw["headers_all"]
    if not isinstance(headers, dict) or len(headers) > 32 or not all(
        isinstance(k, str) and HEADER_NAME.fullmatch(k) and isinstance(v, str)
        and k.lower() not in {"set-cookie", "cookie", "authorization", "proxy-authorization"}
        and v.strip() and len(v) <= 1024 and not any(ord(c) < 32 or ord(c) == 127 for c in v)
        for k, v in headers.items()
    ):
        raise ValueError("invalid header conditions")
    if type(raw["experimental"]) is not bool:
        raise ValueError("experimental must be boolean")
    if raw["outcome"] not in ("potential", "suspicious"):
        raise ValueError("invalid fingerprint outcome")
    return Fingerprint(
        _text(raw["id"]), tuple(codes), body, headers,
        _strings(raw["negative_body"]), raw["experimental"], raw["outcome"],
        _sources(raw["sources"]), _text(raw["limitations"]),
        _text(raw["body_title"]) if raw.get("body_title") is not None else None,
    )


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key[:80]}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


class FingerprintDatabase:
    def __init__(self, providers: list[Provider], warnings: list[str] | None = None) -> None:
        self.providers = providers
        self.warnings = warnings or []

    @classmethod
    def load(cls, path: Path | None = None) -> "FingerprintDatabase":
        source = path if path is not None else files("dangl3").joinpath("data/providers.json")
        try:
            with source.open("rb") as handle:
                payload = handle.read(MAX_DATABASE_BYTES + 1)
            if len(payload) > MAX_DATABASE_BYTES:
                raise ValueError("fingerprint database exceeds 1 MiB")
            raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_keys,
                             parse_constant=_invalid_constant)
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            raise FingerprintDatabaseError(f"cannot load fingerprint database: {exc}") from exc
        if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
            raise FingerprintDatabaseError("unsupported fingerprint database schema")
        if not isinstance(raw.get("providers"), list) or not raw["providers"]:
            raise FingerprintDatabaseError("database must contain provider definitions")
        if len(raw["providers"]) > 64 or set(raw) - {"schema_version", "reviewed_on", "providers"}:
            raise FingerprintDatabaseError("too many providers or unknown database fields")
        providers: list[Provider] = []
        warnings: list[str] = []
        provider_ids: set[str] = set()
        fingerprint_ids: set[str] = set()
        for index, item in enumerate(raw["providers"]):
            try:
                if not isinstance(item, dict):
                    raise ValueError("provider must be an object")
                if set(item) - {"id", "name", "dns_suffixes", "dns_exact", "fingerprints", "limitations",
                                "sources", "last_reviewed", "review_basis"}:
                    raise ValueError("unknown provider fields")
                provider_id = _text(item["id"])
                if provider_id in provider_ids:
                    raise ValueError("duplicate provider id")
                suffixes = _strings(item["dns_suffixes"], nonempty=True)
                if not all(normalize_hostname(x) == x for x in suffixes):
                    raise ValueError("invalid hostname suffix")
                exact = _strings(item.get("dns_exact", []))
                if not all(normalize_hostname(x) == x for x in exact):
                    raise ValueError("invalid exact DNS name")
                if not isinstance(item["fingerprints"], list) or len(item["fingerprints"]) > 32:
                    raise ValueError("fingerprints must be a list")
                # Reject the entire provider if any rule is malformed; never relax a rule.
                rules = tuple(_fingerprint(rule) for rule in item["fingerprints"])
                ids = [rule.id for rule in rules]
                if len(set(ids)) != len(ids) or fingerprint_ids.intersection(ids):
                    raise ValueError("duplicate fingerprint id")
                reviewed = item.get("last_reviewed")
                if reviewed is not None:
                    if not isinstance(reviewed, str) or date.fromisoformat(reviewed).isoformat() != reviewed:
                        raise ValueError("invalid review date")
                    if date.fromisoformat(reviewed) > date.today():
                        raise ValueError("review date is in the future")
                basis = item.get("review_basis", "documentation")
                if basis not in ("documentation", "official_template"):
                    raise ValueError("invalid review basis")
                provider = Provider(provider_id, _text(item["name"]), suffixes, rules,
                                    _text(item["limitations"]), _sources(item["sources"]),
                                    exact, reviewed, basis)
                providers.append(provider)
                provider_ids.add(provider_id)
                fingerprint_ids.update(ids)
            except (KeyError, TypeError, ValueError) as exc:
                message = f"Skipped invalid provider definition {index}: {exc}"
                warnings.append(message)
                logger.warning(message)
        if not providers:
            raise FingerprintDatabaseError("no valid provider definitions remain")
        return cls(providers, warnings)

    def match(self, provider: Provider, response: HTTPResult) -> list[Fingerprint]:
        return [rule for rule in provider.fingerprints if rule.matches(response)]

    def ambiguities(self, provider: Provider, response: HTTPResult) -> list[str]:
        reasons = []
        for rule in provider.fingerprints:
            if response.status_code not in rule.status_codes:
                continue
            if rule.body_matches(response.body):
                if any(_contains(response.body, text) for text in rule.negative_body):
                    reasons.append(f"{rule.id}: positive body conditions conflict with a negative indicator")
                elif not rule.matches(response):
                    reasons.append(f"{rule.id}: body indicators present but required headers or completeness missing")
        return reasons

    def coverage(self) -> list[dict]:
        return [provider.to_dict() for provider in self.providers]
