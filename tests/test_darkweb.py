from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from sentinel.darkweb.matcher import DarkWebMatcher, max_severity
from sentinel.darkweb.pullers import Finding, normalize, value_hash


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
async def test_unmatched_finding_is_stored_without_tenant_match():
    matcher = DarkWebMatcher()
    response = AsyncMock()
    response.data = []
    with patch("sentinel.darkweb.matcher.supabase._retry", return_value=response), patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process({
            "source_id": "hibp", "kind": "email", "matched_value": "user@example.com",
            "context": "breach", "severity": "high", "source_url": None, "metadata": {},
        })
    assert result == {"matched": 0, "alerts": 0}
    record.assert_awaited_once()
    assert record.await_args.args[1:] == (None, None)

@pytest.mark.asyncio
async def test_watchlist_match_fans_out_per_tenant():
    matcher = DarkWebMatcher()
    t1, t2 = str(uuid4()), str(uuid4())
    response = AsyncMock()
    response.data = [
        {"id": str(uuid4()), "tenant_id": t1, "kind": "email", "severity": "high"},
        {"id": str(uuid4()), "tenant_id": t2, "kind": "email", "severity": "critical"},
    ]
    with patch("sentinel.darkweb.matcher.supabase._retry", return_value=response), patch.object(matcher, "_record", new=AsyncMock(return_value={"alert_id": str(uuid4())})) as record:
        result = await matcher.process({
            "source_id": "telegram_public", "kind": "email", "matched_value": "user@example.com",
            "context": "public leak", "severity": "high", "source_url": "https://t.me/s/example", "metadata": {},
        })
    assert result == {"matched": 2, "alerts": 2}
    assert record.await_count == 2
