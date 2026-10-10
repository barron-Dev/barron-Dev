from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import PastePublicMonitor, _paste_ids_from_feed


def test_paste_feed_parser_accepts_only_pastebin_ids():
    feed = """<?xml version="1.0"?>
    <rss><channel>
      <item><link>https://pastebin.com/AbCd1234</link></item>
      <item><link>https://attacker.example/anything</link></item>
      <item><link>https://pastebin.com/raw/AbCd1234</link></item>
      <item><link>https://pastebin.com/ZXcv9876</link></item>
    </channel></rss>"""

    assert _paste_ids_from_feed(feed) == ["AbCd1234", "ZXcv9876"]


def test_paste_feed_parser_fails_closed_on_invalid_xml():
    assert _paste_ids_from_feed("<rss><item>") == []


class _Response:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        return None


class _Client:
    def __init__(self, *args, **kwargs):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url: str, **kwargs):
        self.urls.append(url)
        if url == PastePublicMonitor.FEED:
            return _Response(
                "<rss><channel><item><link>https://pastebin.com/AbCd1234</link></item></channel></rss>"
            )
        if url == "https://pastebin.com/raw/AbCd1234":
            return _Response("exposed identifier: security@owned-example.com; password=not-retained")
        raise AssertionError(f"Unexpected URL requested: {url}")


@pytest.mark.asyncio
async def test_paste_monitor_reads_raw_content_and_returns_source_specific_evidence():
    client = _Client()
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=client):
        findings = await PastePublicMonitor().pull()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.matched_value == "security@owned-example.com"
    assert finding.source_url == "https://pastebin.com/AbCd1234"
    assert finding.metadata == {"paste_id": "AbCd1234"}
    assert "not-retained" not in repr(finding)
    assert client.urls == [
        PastePublicMonitor.FEED,
        "https://pastebin.com/raw/AbCd1234",
    ]
