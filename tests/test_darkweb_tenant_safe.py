from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.pullers import as_domain, normalize, value_hash


def test_domain_normalization_and_hashing():
    assert normalize(" Example.COM ") == "example.com"
    assert value_hash(" CEO@Example.COM ") == value_hash("ceo@example.com")


@pytest.mark.parametrize("value,expected", [
    ("Example.COM", "example.com"),
    ("https://Sub.Example.com/path", "sub.example.com"),
    ("", None),
    ("localhost", None),
    ("bad domain.com", None),
    ("user@example.com", None),
    ("https://user:pass@example.com", None),
    ("-bad.example.com", None),
    ("example..com", None),
    ("127.0.0.1", None),
])
def test_as_domain(value, expected):
    assert as_domain(value) == expected


@pytest.mark.asyncio
async def test_global_unmatched_candidate_is_not_persisted():
    matcher = DarkWebMatcher()
    finding = {"source_id": "ransomwatch", "kind": "domain", "matched_value": "example.com", "metadata": {}}
    with patch.object(matcher, "_lookup_global", new=AsyncMock(return_value=[])), patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process(finding, scope="global")
    assert result["status"] == "unmatched_not_persisted"
    assert result["persisted"] == 0
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_customer_scope_never_falls_back_to_global():
    matcher = DarkWebMatcher()
    tenant_id, watchlist_id = str(uuid4()), str(uuid4())
    finding = {"source_id": "ransomware_live", "kind": "domain", "matched_value": "example.com", "metadata": {}}
    with patch.object(matcher, "_lookup_scoped", new=AsyncMock(return_value=[])) as scoped, patch.object(matcher, "_lookup_global", new=AsyncMock()) as global_lookup, patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process(finding, scope="watchlist", tenant_id=tenant_id, watchlist_id=watchlist_id)
    assert result["status"] == "no_watchlist_match"
    scoped.assert_awaited_once_with("domain", "example.com", tenant_id, watchlist_id)
    global_lookup.assert_not_awaited()
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_scoped_match_records_only_requested_watchlist():
    matcher = DarkWebMatcher()
    tenant_id, watchlist_id = str(uuid4()), str(uuid4())
    watch = {"id": watchlist_id, "tenant_id": tenant_id, "kind": "domain", "severity": "high"}
    finding = {"source_id": "ransomware_live", "kind": "domain", "matched_value": "example.com", "metadata": {}}
    with patch.object(matcher, "_lookup_scoped", new=AsyncMock(return_value=[watch])), patch.object(matcher, "_lookup_global", new=AsyncMock()) as global_lookup, patch.object(matcher, "_record", new=AsyncMock(return_value={"finding_id": 42, "alert_id": "a"})) as record:
        result = await matcher.process(finding, scope="watchlist", tenant_id=tenant_id, watchlist_id=watchlist_id)
    assert result["status"] == "persisted"
    assert result["persisted"] == 1
    global_lookup.assert_not_awaited()
    assert record.await_args.args[1:3] == (tenant_id, watchlist_id)
