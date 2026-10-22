from __future__ import annotations

import asyncio

from cyclothone.darkweb.scheduler import DarkWebScheduler


def test_native_onion_scheduler_is_disabled_without_explicit_flag(monkeypatch):
    monkeypatch.delenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", raising=False)
    scheduler = DarkWebScheduler()

    async def should_not_be_called():
        raise AssertionError("disabled native onion scheduler must not query domains")

    scheduler._tenant_domains = should_not_be_called  # type: ignore[method-assign]

    asyncio.run(scheduler._domain_tick())
