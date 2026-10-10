import pytest
from unittest.mock import AsyncMock

from cyclothone.darkweb.scheduler import DarkWebScheduler
from cyclothone.darkweb.request_worker import _coverage_state


def test_coverage_is_none_when_no_provider_was_checked():
    assert _coverage_state([
        {"source": "hibp", "state": "unavailable", "reason": "missing_key"},
        {"source": "github_code", "state": "failed", "reason": "timeout"},
    ]) == "none"


def test_coverage_is_partial_when_any_provider_is_unavailable_or_failed():
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "unavailable", "reason": "missing_key"},
    ]) == "partial"


def test_coverage_only_says_all_configured_sources_checked_when_every_check_succeeded():
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "checked"},
    ]) == "all_configured_sources_checked"


def test_archived_ransomwatch_is_not_counted_as_fresh_coverage():
    assert _coverage_state([
        {"source": "ransomwatch", "state": "unavailable", "reason": "historical_only_archived_feed"},
        {"source": "pastebin_public", "state": "checked"},
    ]) == "partial"



@pytest.mark.asyncio
async def test_scheduler_does_not_poll_archived_ransomwatch(monkeypatch):
    scheduler = DarkWebScheduler()
    monkeypatch.setenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS", "")
    monkeypatch.setenv("SENTINEL_DW_TELEGRAM_CHANNELS", "")
    monkeypatch.setattr(scheduler, "_enabled_sources", AsyncMock(return_value={"ransomwatch", "pastebin_public"}))
    mark_source = AsyncMock()
    run_pull = AsyncMock()
    monkeypatch.setattr(scheduler, "_mark_source", mark_source)
    monkeypatch.setattr(scheduler, "_run_pull", run_pull)

    await scheduler._global_tick()

    mark_source.assert_awaited_once_with("ransomwatch", "historical_only_archived_feed", pulled=False)
    run_pull.assert_awaited_once()
    assert run_pull.await_args.args[0] == "pastebin_public"
