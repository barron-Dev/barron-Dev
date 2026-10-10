import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from cyclothone.darkweb.matcher import DarkWebMatcher


class _Query:
    def __init__(self, table_name: str, rows_by_table: dict):
        self.table_name = table_name
        self.rows_by_table = rows_by_table
        self.filters = {}

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, key, value):
        self.filters[key] = value
        return self

    def limit(self, *_args):
        return self

    async def execute(self):
        rows = self.rows_by_table.get(self.table_name, [])
        matched = [
            row for row in rows
            if all(str(row.get(key)) == str(value) for key, value in self.filters.items())
        ]
        return SimpleNamespace(data=matched)


class _Client:
    def __init__(self, rows_by_table: dict):
        self.rows_by_table = rows_by_table

    def table(self, table_name: str):
        return _Query(table_name, self.rows_by_table)


async def _retry(callback, attempts=1):
    return await callback()


@pytest.mark.asyncio
async def test_background_matcher_links_hibp_email_to_exact_domain_watch():
    tenant_id = "tenant-1"
    watch_id = "watch-domain-1"
    domain_hash = hashlib.sha256(b"owned-example.com").hexdigest()
    client = _Client({
        "dw_watchlist": [{
            "id": watch_id,
            "tenant_id": tenant_id,
            "kind": "domain",
            "value_hash": domain_hash,
            "severity": "high",
        }],
        "dw_watch_aliases": [],
    })
    matcher = DarkWebMatcher()
    with (
        patch("cyclothone.darkweb.matcher.supabase._ensure", new=AsyncMock(return_value=client)),
        patch("cyclothone.darkweb.matcher.supabase._retry", side_effect=_retry),
        patch.object(matcher, "_record", new=AsyncMock(return_value={"alert_id": "alert-1"})) as record,
    ):
        result = await matcher.process({
            "source_id": "hibp",
            "kind": "email",
            "matched_value": "security@owned-example.com",
            "context": "breach identifier",
            "severity": "high",
            "source_url": None,
            "metadata": {},
        })

    assert result == {"matched": 1, "alerts": 1, "errors": 0}
    assert record.await_args.args[1:] == (tenant_id, watch_id)


@pytest.mark.asyncio
async def test_background_matcher_rejects_lookalike_email_domain():
    tenant_id = "tenant-1"
    watch_id = "watch-domain-1"
    domain_hash = hashlib.sha256(b"owned-example.com").hexdigest()
    client = _Client({
        "dw_watchlist": [{
            "id": watch_id,
            "tenant_id": tenant_id,
            "kind": "domain",
            "value_hash": domain_hash,
            "severity": "high",
        }],
        "dw_watch_aliases": [],
    })
    matcher = DarkWebMatcher()
    with (
        patch("cyclothone.darkweb.matcher.supabase._ensure", new=AsyncMock(return_value=client)),
        patch("cyclothone.darkweb.matcher.supabase._retry", side_effect=_retry),
        patch.object(matcher, "_record", new=AsyncMock(return_value={})) as record,
    ):
        result = await matcher.process({
            "source_id": "telegram_public",
            "kind": "email",
            "matched_value": "security@owned-example.com.attacker.test",
            "context": "public preview",
            "severity": "high",
            "source_url": None,
            "metadata": {},
        })

    assert result == {"matched": 0, "alerts": 0, "errors": 0}
    assert record.await_args.args[1:] == (None, None)
