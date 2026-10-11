from unittest.mock import AsyncMock, patch

import pytest

from cyclothone.darkweb.pullers import MetaPublicMonitor


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeAsyncClient:
    def __init__(self, responses, **kwargs):
        self.responses = iter(responses)
        self.get = AsyncMock(side_effect=lambda *args, **kwargs: next(self.responses))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_meta_search_term_uses_domain_label_not_scheme_or_path():
    assert MetaPublicMonitor._search_term("https://www.ivonix.site/login") == "ivonix"
    assert MetaPublicMonitor._search_term("example.com") == "example"


@pytest.mark.asyncio
async def test_instagram_monitor_fails_closed_without_credentials():
    monitor = MetaPublicMonitor(access_token="", instagram_user_id="", facebook_page_ids=[])
    with pytest.raises(RuntimeError, match="meta_instagram_credentials_required"):
        await monitor.pull_instagram_domains(["example.com"])


@pytest.mark.asyncio
async def test_facebook_monitor_fails_closed_without_access_token():
    monitor = MetaPublicMonitor(access_token="", instagram_user_id="", facebook_page_ids=["123"])
    with pytest.raises(RuntimeError, match="meta_facebook_access_token_required"):
        await monitor.pull_facebook_domains(["example.com"])


@pytest.mark.asyncio
async def test_facebook_monitor_fails_closed_without_configured_page_ids():
    monitor = MetaPublicMonitor(access_token="configured-token", instagram_user_id="", facebook_page_ids=[])
    with pytest.raises(RuntimeError, match="meta_facebook_page_ids_required"):
        await monitor.pull_facebook_domains(["example.com"])


@pytest.mark.asyncio
async def test_facebook_match_returns_permalink_without_retaining_post_text():
    client = FakeAsyncClient([FakeResponse({"data": [{
        "id": "123_456",
        "message": "Security note: example.com may be exposed",
        "permalink_url": "https://www.facebook.com/example/posts/456",
        "created_time": "2026-10-10T12:00:00+0000",
    }]})])
    monitor = MetaPublicMonitor(access_token="test-token", facebook_page_ids=["123"])
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=client):
        findings = await monitor.pull_facebook_domains(["example.com"])
    assert len(findings) == 1
    assert findings[0].source_id == "facebook_public"
    assert findings[0].matched_value == "example.com"
    assert findings[0].source_url == "https://www.facebook.com/example/posts/456"
    assert "Security note" not in str(findings[0].metadata)
    assert "Security note" not in str(findings[0].context)
