from unittest.mock import patch

import pytest

from cyclothone.darkweb.native_onion import NativeOnionCrawler, configured_onion_seeds


class _Response:
    status_code = 200
    headers = {"content-type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    def __init__(self, body):
        self.content = body


class _Client:
    def __init__(self, *args, **kwargs):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        self.urls.append(url)
        if url.endswith("/"):
            return _Response(
                b'<html><body>owned-example.com '
                b'<a href="/leak">detail</a>'
                b'<a href="https://example.com/outside">outside</a></body></html>'
            )
        return _Response(b"<html><body>owned-example.com appeared</body></html>")


def test_configured_onion_seeds_reject_non_onion_and_private_urls():
    with patch.dict("os.environ", {
        "CYCLOTHONE_DW_ONION_SEEDS":
            "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/,"
            "https://example.com/,http://user:pass@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/"
    }):
        seeds = configured_onion_seeds()
    assert len(seeds) == 1
    assert seeds[0].endswith(".onion/")


@pytest.mark.asyncio
async def test_native_crawler_only_follows_same_onion_host_and_records_exact_evidence():
    crawler = NativeOnionCrawler(
        seeds=["http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"],
        proxy="socks5://127.0.0.1:9050",
    )
    with patch("cyclothone.darkweb.native_onion.httpx.AsyncClient", _Client):
        findings = await crawler.pull("domain", "owned-example.com")

    assert crawler.pages_checked == 2
    assert crawler.seed_status == {
        "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/": "checked"
    }
    assert len(findings) == 2
    assert all(f.kind == "domain" and f.matched_value == "owned-example.com" for f in findings)
    assert all(f.metadata["exposure_layer"] == "dark" for f in findings)
    assert all(f.metadata["access_mode"] == "tor_public_onion" for f in findings)
    assert all("outside" not in (f.source_url or "") for f in findings)


@pytest.mark.asyncio
async def test_native_crawler_fails_closed_without_seed_configuration():
    crawler = NativeOnionCrawler(seeds=[], proxy="socks5://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="native_onion_missing_seeds"):
        await crawler.pull("domain", "owned-example.com")
