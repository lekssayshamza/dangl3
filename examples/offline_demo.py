"""Run after installation: python examples/offline_demo.py (no network)."""

import httpx

from dangl3.async_http_client import AsyncHTTPInspector
from dangl3.models import DNSResult, DNSStatus, ScanConfig
from dangl3.reporting import build_report, report_json
from dangl3.scanner import Scanner


class FixtureResolver:
    async def resolve(self, hostname: str) -> DNSResult:
        target = {"blog.example.com": "demo.s3-website-us-east-1.amazonaws.com",
                  "app.example.com": "demo.vercel.app",
                  "docs.example.com": "demo.github.io"}[hostname]
        return DNSResult(hostname, DNSStatus.RESOLVED,
                         cname_chain=[target],
                         records={hostname: {"CNAME": [target]}, target: {
                             "CNAME": [], "A": ["93.184.216.34"], "AAAA": [],
                         }},
                         a=["93.184.216.34"])


def handler(request: httpx.Request) -> httpx.Response:
    if request.headers["host"] != "blog.example.com":
        body = b"DEPLOYMENT_NOT_FOUND" if request.headers["host"] == "app.example.com" else b"Not Found"
        return httpx.Response(404, stream=httpx.ByteStream(body))
    return httpx.Response(
        404, headers={"Server": "AmazonS3"},
        stream=httpx.ByteStream(b"NoSuchBucket: The specified bucket does not exist"),
    )


if __name__ == "__main__":
    config = ScanConfig()
    resolver = FixtureResolver()
    inspector = AsyncHTTPInspector(config, resolver, transport_factory=lambda: httpx.MockTransport(handler))
    scanner = Scanner(config, resolver=resolver, inspector=inspector)
    report = build_report(scanner.scan(["blog.example.com", "app.example.com", "docs.example.com"]), config,
                          duration_seconds=scanner.duration_seconds, provider_coverage=scanner.database.coverage())
    report["warnings"].append("OFFLINE DEMONSTRATION: synthetic DNS and HTTP evidence, not a live finding.")
    print(report_json(report), end="")
