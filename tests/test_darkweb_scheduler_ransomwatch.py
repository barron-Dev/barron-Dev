from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cyclothone.darkweb.scheduler import DarkWebScheduler


@pytest.mark.asyncio
async def test_global_tick_polls_ransomwatch_on_its_30_minute_cadence(monkeypatch):
    scheduler = DarkWebScheduler()
    monkeypatch.setattr(scheduler, "_enabled_sources", AsyncMock(return_value={"ransomwatch"}))
    pull = AsyncMock()
    monkeypatch.setattr(scheduler, "_run_pull", pull)

    await scheduler._global_tick()
    pull.assert_awaited_once()
    assert pull.await_args.args[0] == "ransomwatch"
    assert pull.await_args.kwargs["monitor"].SOURCE == "ransomwatch"

    pull.reset_mock()
    await scheduler._global_tick()
    pull.assert_not_awaited()


@pytest.mark.asyncio
async def test_global_tick_skips_ransomwatch_when_source_disabled(monkeypatch):
    scheduler = DarkWebScheduler()
    monkeypatch.setattr(scheduler, "_enabled_sources", AsyncMock(return_value=set()))
    pull = AsyncMock()
    monkeypatch.setattr(scheduler, "_run_pull", pull)

    await scheduler._global_tick()
    pull.assert_not_awaited()
