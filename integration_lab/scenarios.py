"""Synthetic scenarios; classifications always come from the production scanner."""

from dataclasses import dataclass
from importlib.resources import files
import json

from dangl3.models import Classification


@dataclass(frozen=True)
class Scenario:
    id: str
    target: str
    fixture: str | None
    expected: Classification
    blocked: bool = False

    @property
    def hostname(self) -> str:
        return f"{self.id}.dangl3.test"


S3 = "s3-website-us-east-1.amazonaws.com"
SCENARIOS = (
    Scenario("missing-s3", f"missing-s3.{S3}", "s3_missing", Classification.POTENTIAL_TAKEOVER),
    Scenario("missing-vercel", "missing-vercel.vercel.app", "vercel_missing", Classification.SUSPICIOUS),
    Scenario("github-dns-only", "dns-only.github.io", "generic_404", Classification.UNKNOWN),
    Scenario("generic-404", f"generic-404.{S3}", "generic_404", Classification.NO_EVIDENCE),
    Scenario("healthy", f"healthy.{S3}", "healthy", Classification.NO_EVIDENCE),
    Scenario("ambiguous", f"ambiguous.{S3}", "ambiguous", Classification.UNKNOWN),
    Scenario("body-limit", f"body-limit.{S3}", "body_limit", Classification.UNKNOWN),
    Scenario("unsafe-redirect", f"unsafe-redirect.{S3}", "unsafe_redirect", Classification.UNKNOWN, True),
    Scenario("dns-rebinding", f"dns-rebinding.{S3}", "rebind_redirect", Classification.UNKNOWN, True),
    Scenario("incomplete-http", f"incomplete-http.{S3}", "incomplete", Classification.UNKNOWN),
    Scenario("nxdomain", "", None, Classification.NO_EVIDENCE),
    Scenario("cname-loop", "loop-peer.dangl3.test", None, Classification.UNKNOWN),
)
BY_HOST = {scenario.hostname: scenario for scenario in SCENARIOS}
LOOP_PEER = "loop-peer.dangl3.test"


def load_responses() -> dict:
    return json.loads(files("integration_lab").joinpath("fixtures/responses.json").read_text(encoding="utf-8"))
