from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from cyclothone.darkweb.matcher import DarkWebMatcher, max_severity
from cyclothone.darkweb.pullers import Finding, normalize, value_hash


def test_identifier_hash_is_normalized():
    assert value_hash(" CEO@Example.COM ") == value_hash("ceo@example.com")
    assert normalize(" Example.COM ") == "example.com"


def test_severity_escalates():
    assert max_severity("high", "critical") == "critical"
    assert max_severity("critical", "medium") == "critical"
    assert max_severity("medium", "high") == "high"


def test_finding_is_immutable():
    finding = Finding("hibp", "email", "a@example.com", None, "high", None, {})
    with pytest.raises(AttributeError):
        finding.severity = "critical"

@pytest.mark.asyncio
async def test_unmatched_finding_is_not_persisted_without_tenant_match():
    matcher = DarkWebMatcher()
    finding = {
        "source_id": "hibp", "kind": "email", "matched_value": "user@example.com",
        "context": "breach", "severity": "high", "source_url": None, "metadata": {},
    }
    with patch.object(matcher, "_lookup_global", new=AsyncMock(return_value=[])), patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process(finding, scope="global")
    assert result == {"status": "unmatched_not_persisted", "matched": 0, "persisted": 0, "alerts": 0, "errors": 0}
    record.assert_not_awaited()

@pytest.mark.asyncio
async def test_watchlist_match_fans_out_per_tenant():
    matcher = DarkWebMatcher()
    t1, t2 = str(uuid4()), str(uuid4())
    watches = [
        {"id": str(uuid4()), "tenant_id": t1, "kind": "email", "severity": "high"},
        {"id": str(uuid4()), "tenant_id": t2, "kind": "email", "severity": "critical"},
    ]
    with patch.object(matcher, "_lookup_global", new=AsyncMock(return_value=watches)), patch.object(
        matcher, "_record", new=AsyncMock(side_effect=[
            {"finding_id": 1, "alert_id": str(uuid4())},
            {"finding_id": 2, "alert_id": str(uuid4())},
        ])
    ) as record:
        result = await matcher.process({
            "source_id": "telegram_public", "kind": "email", "matched_value": "user@example.com",
            "context": "public leak", "severity": "high", "source_url": "https://t.me/s/example", "metadata": {},
        }, scope="global")
    assert result == {"status": "persisted", "matched": 2, "persisted": 2, "alerts": 2, "errors": 0}
    assert record.await_count == 2
