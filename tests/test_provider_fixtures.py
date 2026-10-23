import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from dangl3.models import DNSResult, DNSStatus, HTTPResult
from dangl3.scanner import Scanner

CASES = json.loads(Path(__file__).with_name("fixtures").joinpath("provider_cases.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_provider_positive_negative_and_ambiguous_fixtures(case, database):
    resolver, inspector = AsyncMock(), AsyncMock()
    resolver.resolve.return_value = DNSResult(
        "fixture.example.com", DNSStatus.RESOLVED, cname_chain=[case["cname"]], a=["93.184.216.34"],
    )
    inspector.inspect.return_value = HTTPResult(
        status_code=case["status_code"], headers=case["headers"], body=case["body"],
        body_truncated=case["body_truncated"], complete=True,
    )
    result = asyncio.run(Scanner(database=database, resolver=resolver, inspector=inspector).scan_async(["fixture.example.com"]))[0]
    assert result.provider["id"] == case["provider"]
    assert result.classification.value == case["expected"]
    assert result.explanation and result.structured_evidence
    if not result.provider["fingerprint_available"]:
        assert not result.matched_fingerprints
