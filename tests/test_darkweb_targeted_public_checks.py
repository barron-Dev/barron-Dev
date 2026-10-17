import json
from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import PastePublicMonitor, TelegramPublicMonitor


class _Response:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return json.loads(self.text)


class _Client:
    responses = {}
    requested = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        type(self).requested.append(url)
        for prefix, response in type(self).responses.items():
            if url.startswith(prefix):
                return response
        raise AssertionError(f"unexpected test URL: {url}")


@pytest.mark.asyncio
async def test_telegram_request_checks_the_submitted_domain_not_unrelated_emails():
    _Client.responses = {
        "https://t.me/s/": _Response(
            '<div>Public post references EXAMPLE.org; unrelated user someone@else.test</div>'
        )
    }
    _Client.requested = []
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", _Client):
        monitor = TelegramPublicMonitor(["public_channel"])
        findings = await monitor.pull("domain", "example.org")

    assert monitor.channel_status == {"public_channel": "checked"}
    assert len(findings) == 1
    assert findings[0].kind == "domain"
    assert findings[0].matched_value == "example.org"
    assert "observed_text_sha256" in findings[0].metadata
    assert "EXAMPLE.org" not in str(findings[0].metadata)


@pytest.mark.asyncio
async def test_paste_request_checks_submitted_domain_only_after_fetching_raw_content():
    _Client.responses = {
        "https://pastebin.ca/api/v1/feed": _Response(json.dumps({
            "items": [{
                "id": "23456789AB",
                "raw_url": "https://pastebin.ca/raw/23456789AB",
                "url": "https://pastebin.ca/23456789AB",
            }]
        })),
        "https://pastebin.ca/raw/23456789AB": _Response(
            "domain example.org and unrelated person@else.test"
        ),
    }
    _Client.requested = []
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", _Client):
        monitor = PastePublicMonitor()
        findings = await monitor.pull("domain", "example.org")

    assert monitor.items_checked == 1
    assert len(findings) == 1
    assert findings[0].kind == "domain"
    assert findings[0].matched_value == "example.org"
    assert "observed_text_sha256" in findings[0].metadata
    assert "example.org and unrelated" not in str(findings[0].metadata)
    assert any(url.startswith("https://pastebin.ca/raw/") for url in _Client.requested)
