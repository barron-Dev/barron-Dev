from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import PastePublicMonitor, _paste_entries_from_feed


def test_paste_feed_parser_accepts_only_valid_pastebin_ca_entries():
    feed = """{
      "items": [
        {"id":"2abcdefghj","url":"https://pastebin.ca/p/2abcdefghj","raw_url":"https://raw.anybin.ca/raw/2abcdefghj"},
        {"id":"2abcdefghj","url":"https://pastebin.ca/p/2abcdefghj","raw_url":"https://raw.anybin.ca/raw/2abcdefghj"},
        {"id":"3bcdefghjk","url":"https://pastebin.ca/p/3bcdefghjk","raw_url":"https://raw.anybin.ca/raw/3bcdefghjk"},
        {"id":"4cdefghjkm","url":"https://pastebin.ca/p/4cdefghjkm","raw_url":"https://attacker.example/raw/4cdefghjkm"}
      ]
    }"""

    assert _paste_entries_from_feed(feed) == [
        ("2abcdefghj", "https://raw.anybin.ca/raw/2abcdefghj", "https://pastebin.ca/p/2abcdefghj"),
        ("3bcdefghjk", "https://raw.anybin.ca/raw/3bcdefghjk", "https://pastebin.ca/p/3bcdefghjk"),
    ]


def test_paste_feed_parser_rejects_invalid_json_instead_of_reporting_zero_results():
    with pytest.raises(ValueError, match="paste_feed_invalid_json"):
        _paste_entries_from_feed("{invalid json")


def test_paste_feed_parser_rejects_unexpected_schema():
    with pytest.raises(ValueError, match="paste_feed_invalid_schema"):
        _paste_entries_from_feed('{"results": []}')


def test_paste_feed_parser_accepts_a_valid_empty_feed():
    assert _paste_entries_from_feed('{"items": []}') == []


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
                '{"items":[{"id":"2abcdefghj","url":"https://pastebin.ca/p/2abcdefghj","raw_url":"https://raw.anybin.ca/raw/2abcdefghj"}]}'
            )
        if url == "https://raw.anybin.ca/raw/2abcdefghj":
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
    assert finding.source_url == "https://pastebin.ca/p/2abcdefghj"
    assert finding.metadata == {"paste_id": "2abcdefghj"}
    assert "not-retained" not in repr(finding)
    assert client.urls == [
        PastePublicMonitor.FEED,
        "https://raw.anybin.ca/raw/2abcdefghj",
    ]
