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


def test_temporal_archive_write_requires_database_count_confirmation():
    from cyclothone.darkweb.scheduler import _require_temporal_archive_confirmation

    _require_temporal_archive_confirmation([{"accepted_count": 3}], 3)
    _require_temporal_archive_confirmation([{"accepted_count": 0}], 0)


def test_temporal_archive_write_fails_closed_on_partial_or_unconfirmed_write():
    from cyclothone.darkweb.scheduler import _require_temporal_archive_confirmation

    with pytest.raises(RuntimeError, match="ransomwatch_temporal_archive_unconfirmed"):
        _require_temporal_archive_confirmation([{"accepted_count": 2}], 3)
    with pytest.raises(RuntimeError, match="ransomwatch_temporal_archive_unconfirmed"):
        _require_temporal_archive_confirmation(None, 0)
