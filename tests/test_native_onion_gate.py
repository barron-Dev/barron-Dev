from __future__ import annotations

import pytest

from cyclothone.darkweb.native_onion import _safe_onion_url
from cyclothone.darkweb.scheduler import DarkWebScheduler


def test_native_onion_requires_v3_hostname():
    assert _safe_onion_url(f"http://{'a' * 56}.onion/") is not None
    assert _safe_onion_url("http://shortname.onion/") is None
    assert _safe_onion_url(f"http://{'a' * 55}.onion/") is None
    assert _safe_onion_url(f"http://{'a' * 56}x.onion/") is None


@pytest.mark.asyncio
async def test_native_onion_seed_registry_is_closed_when_feature_gate_off(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", "false")
    monkeypatch.setenv("CYCLOTHONE_DW_ONION_SEEDS", f"http://{'a' * 56}.onion/")
    seeds, origins, discovered = await DarkWebScheduler()._onion_seed_urls()
    assert seeds == []
    assert origins == {}
    assert discovered == {}


@pytest.mark.asyncio
async def test_domain_tick_reports_disabled_gate_without_crawling(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", "false")
    scheduler = DarkWebScheduler()
    calls = []

    async def mark_source(source_id, status, *, pulled=True):
        calls.append((source_id, status, pulled))

    async def forbidden(*args, **kwargs):
        raise AssertionError("must not query or crawl while gate is off")

    scheduler._mark_source = mark_source
    scheduler._tenant_domains = forbidden
    scheduler._enabled_sources = forbidden
    await scheduler._domain_tick()
    assert calls == [("native_onion", "disabled_by_feature_gate", False)]
