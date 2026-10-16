from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from cyclothone.darkweb.matcher import DarkWebMatcher, max_severity
from cyclothone.darkweb.pullers import Finding, as_domain, normalize, value_hash


def test_identifier_hash_is_normalized():
    assert value_hash(" CEO@Example.COM ") == value_hash("ceo@example.com")
    assert normalize(" Example.COM ") == "example.com"


def test_domain_parser_accepts_bare_domain_and_url():
    assert as_domain("Example.COM") == "example.com"
    assert as_domain("https://sub.example.com/path") == "sub.example.com"


@pytest.mark.parametrize("value", ["", "localhost", "bad domain.com", "user@example.com", "https://user:pass@example.com", "-bad.example.com", "example..com", "127.0.0.1"])
def test_domain_parser_rejects_invalid_target(value):
    assert as_domain(value) is None


def test_severity_escalates():
    assert max_severity("high", "critical") == "critical"
    assert max_severity("critical", "medium") == "critical"
    assert max_severity("medium", "high") == "high"


def test_finding_is_immutable():
    finding = Finding("hibp", "email", "a@example.com", None, "high", None, {})
    with pytest.raises(AttributeError):
        finding.severity = "critical"


@pytest.mark.asyncio
async def test_unmatched_global_candidate_is_not_persisted_by_default():
    matcher = DarkWebMatcher()
    with patch.object(matcher, "_lookup_global", new=AsyncMock(return_value=[])), patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process({
            "source_id": "hibp", "kind": "email", "matched_value": "user@example.com",
            "context": "breach", "severity": "high", "source_url": None, "metadata": {},
        }, scope="global")
    assert result == {"status": "unmatched_not_persisted", "matched": 0, "persisted": 0, "alerts": 0, "errors": 0}
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_global_match_fans_out_with_tenant_specific_persistence():
    matcher = DarkWebMatcher()
    t1, t2 = str(uuid4()), str(uuid4())
    watches = [
        {"id": str(uuid4()), "tenant_id": t1, "kind": "email", "severity": "high"},
        {"id": str(uuid4()), "tenant_id": t2, "kind": "email", "severity": "critical"},
    ]
    with patch.object(matcher, "_lookup_global", new=AsyncMock(return_value=watches)), patch.object(
        matcher, "_record", new=AsyncMock(side_effect=[{"finding_id": 11, "alert_id": "a"}, {"finding_id": 12, "alert_id": "b"}])
    ) as record:
        result = await matcher.process({
            "source_id": "telegram_public", "kind": "email", "matched_value": "user@example.com",
            "context": "public leak", "severity": "high", "source_url": "https://t.me/s/example", "metadata": {},
        }, scope="global")
    assert result == {"status": "persisted", "matched": 2, "persisted": 2, "alerts": 2, "errors": 0}
    assert record.await_count == 2
    assert all(call.kwargs["tenant_scoped"] for call in record.await_args_list)


@pytest.mark.asyncio
async def test_customer_scope_never_falls_back_to_global():
    matcher = DarkWebMatcher()
    tenant_id, watchlist_id = str(uuid4()), str(uuid4())
    with patch.object(matcher, "_lookup_scoped", new=AsyncMock(return_value=[])) as scoped, patch.object(
        matcher, "_lookup_global", new=AsyncMock()
    ) as global_lookup, patch.object(matcher, "_record", new=AsyncMock()) as record:
        result = await matcher.process({
            "source_id": "ransomware_live", "kind": "domain", "matched_value": "example.com",
            "context": "public listing", "severity": "high", "source_url": None, "metadata": {},
        }, scope="watchlist", tenant_id=tenant_id, watchlist_id=watchlist_id)
    assert result["status"] == "no_watchlist_match"
    scoped.assert_awaited_once_with("domain", "example.com", tenant_id, watchlist_id)
    global_lookup.assert_not_awaited()
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_customer_scope_persists_only_requested_watchlist():
    matcher = DarkWebMatcher()
    tenant_id, watchlist_id = str(uuid4()), str(uuid4())
    watch = {"id": watchlist_id, "tenant_id": tenant_id, "kind": "domain", "severity": "high"}
    with patch.object(matcher, "_lookup_scoped", new=AsyncMock(return_value=[watch])), patch.object(
        matcher, "_lookup_global", new=AsyncMock()
    ) as global_lookup, patch.object(
        matcher, "_record", new=AsyncMock(return_value={"finding_id": 42, "alert_id": "alert-1"})
    ) as record:
        result = await matcher.process({
            "source_id": "ransomware_live", "kind": "domain", "matched_value": "example.com",
            "context": "public listing", "severity": "high", "source_url": None, "metadata": {},
        }, scope="watchlist", tenant_id=tenant_id, watchlist_id=watchlist_id)
    assert result == {"status": "persisted", "matched": 1, "persisted": 1, "alerts": 1, "errors": 0}
    global_lookup.assert_not_awaited()
    assert record.await_args.args[1:3] == (tenant_id, watchlist_id)
    assert record.await_args.kwargs["tenant_scoped"] is True


@pytest.mark.asyncio
async def test_customer_scope_requires_tenant_and_watchlist():
    result = await DarkWebMatcher().process(
        {"source_id": "x", "kind": "domain", "matched_value": "example.com"},
        scope="watchlist", tenant_id=str(uuid4()),
    )
    assert result["status"] == "scope_required"
    assert result["errors"] == 1
