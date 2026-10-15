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
async def test_unmatched_finding_is_stored_without_tenant_match():
    matcher = DarkWebMatcher()
    response = AsyncMock()
    response.data = []
    with patch("cyclothone.darkweb.matcher.supabase._retry", return_value=response), patch.object(matcher, "_record", new=AsyncMock(return_value={})) as record:
        result = await matcher.process({
            "source_id": "hibp", "kind": "email", "matched_value": "user@example.com",
            "context": "breach", "severity": "high", "source_url": None, "metadata": {},
        })
    assert result == {"matched": 0, "alerts": 0, "errors": 0}
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
    with patch("cyclothone.darkweb.matcher.supabase._retry", return_value=response), patch.object(matcher, "_record", new=AsyncMock(return_value={"alert_id": str(uuid4())})) as record:
        result = await matcher.process({
            "source_id": "telegram_public", "kind": "email", "matched_value": "user@example.com",
            "context": "public leak", "severity": "high", "source_url": "https://t.me/s/example", "metadata": {},
        })
    assert result == {"matched": 2, "alerts": 2, "errors": 0}
    assert record.await_count == 2


@pytest.mark.asyncio
async def test_provider_execution_uses_atomic_state_rpc_not_channel_inventory():
    from cyclothone.darkweb.source_registry import record_provider_execution

    with patch("cyclothone.darkweb.source_registry.supabase.rpc", new=AsyncMock()) as rpc, patch(
        "cyclothone.darkweb.source_registry.TelegramSourceRegistry.event", new=AsyncMock()
    ) as event:
        await record_provider_execution("hibp", "ok", pulled=True)

    rpc.assert_awaited_once_with("record_dw_source_execution", {
        "p_source_id": "hibp",
        "p_status": "ok",
        "p_pulled": True,
        "p_error": None,
    })
    event.assert_awaited_once()
    assert event.await_args.args[0] == "provider:hibp"
    assert event.await_args.args[1] == "provider_execution"


@pytest.mark.asyncio
async def test_provider_execution_rejects_invalid_provider_identity():
    from cyclothone.darkweb.source_registry import record_provider_execution

    with patch("cyclothone.darkweb.source_registry.supabase.rpc", new=AsyncMock()) as rpc:
        await record_provider_execution("not a provider id!", "ok", pulled=True)

    rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_customer_findings_and_alerts_are_paged_past_single_page_cap():
    from types import SimpleNamespace

    from cyclothone.darkweb.request_worker import (
        _load_tenant_alerts,
        _load_watchlist_findings,
    )

    tenant_id, watchlist_id = str(uuid4()), str(uuid4())
    finding_rows = [
        {"id": str(i), "tenant_id": tenant_id, "watchlist_id": watchlist_id}
        for i in range(5)
    ]
    alert_rows = [
        {"id": str(i), "tenant_id": tenant_id, "title": f"alert-{i}"}
        for i in range(5)
    ]

    class Query:
        def __init__(self, rows):
            self.rows = rows
            self.filters = []
            self.start, self.end = 0, 9999

        def select(self, _columns):
            return self

        def eq(self, key, value):
            self.filters.append((key, value))
            return self

        def order(self, *_args, **_kwargs):
            return self

        def range(self, start, end):
            self.start, self.end = start, end
            return self

        async def execute(self):
            rows = self.rows
            for key, value in self.filters:
                rows = [row for row in rows if row.get(key) == value]
            return SimpleNamespace(data=rows[self.start:self.end + 1])

    class Client:
        def table(self, name):
            return Query(finding_rows if name == "dw_findings" else alert_rows)

    async def retry(operation, attempts=2):
        return await operation()

    with patch("cyclothone.darkweb.request_worker.supabase._ensure", new=AsyncMock(return_value=Client())), patch(
        "cyclothone.darkweb.request_worker.supabase._retry", side_effect=retry
    ):
        findings = await _load_watchlist_findings(tenant_id, watchlist_id, page_size=2)
        alerts = await _load_tenant_alerts(tenant_id, page_size=2)

    assert [row["id"] for row in findings] == ["0", "1", "2", "3", "4"]
    assert [row["id"] for row in alerts] == ["0", "1", "2", "3", "4"]


def test_historical_correlation_requires_exact_identifier_or_exact_email_domain():
    from cyclothone.darkweb.request_worker import _historical_finding_matches_target

    assert _historical_finding_matches_target(
        {"kind": "domain", "matched_value": "example.com"}, "domain", "example.com"
    )
    assert _historical_finding_matches_target(
        {"kind": "email", "matched_value": "person@example.com"}, "domain", "example.com"
    )
    assert not _historical_finding_matches_target(
        {"kind": "domain", "matched_value": "notexample.com"}, "domain", "example.com"
    )
    assert not _historical_finding_matches_target(
        {"kind": "company_name", "matched_value": "Example"}, "domain", "example.com"
    )
