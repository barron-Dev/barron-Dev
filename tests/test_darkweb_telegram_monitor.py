from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import TelegramPublicMonitor


class _Response:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        return None


class _Client:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url: str, **kwargs):
        if "broken-channel" in url:
            raise RuntimeError("source unavailable")
        channel = url.rsplit("/", 1)[-1]
        return _Response(f"<div>security-{channel}@owned-example.com</div>")


@pytest.mark.asyncio
async def test_telegram_monitor_queries_all_configured_channels_and_keeps_source_urls():
    monitor = TelegramPublicMonitor(["@channel-one", "channel-two", "channel-one"])
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=_Client()):
        findings = await monitor.pull()

    assert {finding.matched_value for finding in findings} == {
        "security-channel-one@owned-example.com",
        "security-channel-two@owned-example.com",
    }
    assert {finding.source_url for finding in findings} == {
        "https://t.me/s/channel-one",
        "https://t.me/s/channel-two",
    }
    assert monitor.channel_status == {"channel-one": "checked", "channel-two": "checked"}


@pytest.mark.asyncio
async def test_telegram_monitor_preserves_partial_channel_failure_status():
    monitor = TelegramPublicMonitor(["channel-one", "broken-channel"])
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=_Client()):
        findings = await monitor.pull()

    assert [finding.matched_value for finding in findings] == [
        "security-channel-one@owned-example.com"
    ]
    assert monitor.channel_status == {
        "channel-one": "checked",
        "broken-channel": "failed",
    }


@pytest.mark.asyncio
async def test_telegram_monitor_fails_when_every_configured_channel_fails():
    monitor = TelegramPublicMonitor(["broken-channel"])
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=_Client()):
        with pytest.raises(RuntimeError, match="all configured Telegram public channels failed"):
            await monitor.pull()
    assert monitor.channel_status == {"broken-channel": "failed"}
