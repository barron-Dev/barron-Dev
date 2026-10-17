import pytest
from unittest.mock import AsyncMock

from cyclothone.darkweb.scheduler import (
    DEFAULT_PUBLIC_TELEGRAM_CHANNELS,
    DarkWebScheduler,
    _configured_telegram_channels,
)
from cyclothone.darkweb.native_onion import NativeOnionCrawler
from cyclothone.darkweb.request_worker import _coverage_state, _source_is_enabled


def test_coverage_is_none_when_no_implemented_live_provider_was_checked():
    assert _coverage_state([
        {"source": "native_onion", "availability": "implemented", "state": "unavailable", "reason": "tor_unreachable"},
        {"source": "github_code", "availability": "planned", "state": "failed", "reason": "not_implemented"},
        {"source": "ransomwatch", "availability": "historical_only", "state": "checked"},
    ]) == "none"


def test_coverage_is_partial_when_any_implemented_live_provider_is_unavailable_or_failed():
    assert _coverage_state([
        {"source": "pastebin_public", "availability": "implemented", "state": "checked"},
        {"source": "native_onion", "availability": "implemented", "state": "unavailable", "reason": "tor_unreachable"},
        {"source": "github_code", "availability": "planned", "state": "unavailable"},
    ]) == "partial"


def test_coverage_only_says_all_live_sources_checked_when_every_live_check_succeeded():
    assert _coverage_state([
        {"source": "pastebin_public", "availability": "implemented", "state": "checked"},
        {"source": "telegram_public", "availability": "implemented", "state": "checked"},
        {"source": "ransomwatch", "availability": "historical_only", "state": "unavailable"},
        {"source": "github_code", "availability": "planned", "state": "unavailable"},
    ]) == "all_configured_sources_checked"


def test_archived_ransomwatch_is_not_counted_as_fresh_coverage():
    assert _coverage_state([
        {"source": "ransomwatch", "availability": "historical_only", "state": "unavailable", "reason": "historical_only_archived_feed"},
        {"source": "pastebin_public", "availability": "implemented", "state": "checked"},
    ]) == "all_configured_sources_checked"


def test_telegram_defaults_use_only_the_supplied_public_handles(monkeypatch):
    monkeypatch.delenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS", raising=False)
    monkeypatch.delenv("SENTINEL_DW_TELEGRAM_CHANNELS", raising=False)

    channels = _configured_telegram_channels()
    assert channels == list(DEFAULT_PUBLIC_TELEGRAM_CHANNELS)
    assert len(channels) == 25
    assert {"opendataleaks", "baseleak", "NullLeak", "DWI_OFFICIAL", "DarkfeedNews", "txtbaseslog", "Developer_Astra", "darkside_hubb", "TXT_LOG_ALIEN", "LeakBase", "CodeBreachLab", "ExploitService"}.issubset(set(channels))
    assert "Ares private channel" not in channels


def test_telegram_env_normalizes_public_urls_and_deduplicates(monkeypatch):
    monkeypatch.setenv(
        "CYCLOTHONE_DW_TELEGRAM_CHANNELS",
        "@gladdos69_official,https://t.me/s/ObserverCloud,t.me/observercloud,https://t.me/+privateInvite",
    )

    assert _configured_telegram_channels() == ["gladdos69_official", "ObserverCloud"]


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


@pytest.mark.asyncio
async def test_scheduler_marks_telegram_unavailable_when_explicitly_unconfigured(monkeypatch):
    scheduler = DarkWebScheduler()
    monkeypatch.setenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS", "")
    monkeypatch.setattr(scheduler, "_enabled_sources", AsyncMock(return_value={"telegram_public"}))
    mark_source = AsyncMock()
    run_pull = AsyncMock()
    monkeypatch.setattr(scheduler, "_mark_source", mark_source)
    monkeypatch.setattr(scheduler, "_run_pull", run_pull)

    await scheduler._global_tick()

    mark_source.assert_awaited_once_with("telegram_public", "unavailable_missing_channel", pulled=False)
    run_pull.assert_not_awaited()



def test_native_onion_config_fallback_only_applies_before_source_registration():
    assert _source_is_enabled("native_onion", set(), set())
    assert not _source_is_enabled("native_onion", set(), {"native_onion"})
    assert _source_is_enabled("native_onion", {"native_onion"}, {"native_onion"})


def test_non_native_sources_still_require_enabled_registry_rows():
    assert not _source_is_enabled("pastebin_public", set(), set())
    assert not _source_is_enabled("pastebin_public", set(), {"pastebin_public"})
    assert _source_is_enabled("pastebin_public", {"pastebin_public"}, {"pastebin_public"})


class _EmptyBodyResponse:
    status_code = 200
    headers = {"content-type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    async def aiter_bytes(self):
        yield b"  \n\t"


class _EmptyBodyStream:
    def __init__(self):
        self.response = _EmptyBodyResponse()

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *args):
        return False


class _EmptyBodyClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, url):
        return _EmptyBodyStream()


@pytest.mark.asyncio
async def test_empty_onion_response_is_not_counted_as_a_checked_page(monkeypatch):
    seed = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"
    monkeypatch.setattr("cyclothone.darkweb.native_onion.httpx.AsyncClient", _EmptyBodyClient)
    crawler = NativeOnionCrawler(seeds=[seed], proxy="socks5://127.0.0.1:9050")

    with pytest.raises(RuntimeError, match="native_onion_no_seed_reachable"):
        await crawler.pull("domain", "owned-example.com")

    assert crawler.pages_checked == 0
    assert crawler.pages_failed == 1
    assert crawler.seed_status[seed] == "failed"
