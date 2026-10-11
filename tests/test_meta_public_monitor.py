
import pytest

from cyclothone.darkweb.pullers import MetaPublicMonitor


    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


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
