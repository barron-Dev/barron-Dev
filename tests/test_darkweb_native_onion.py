from unittest.mock import patch

import pytest

from cyclothone.darkweb.native_onion import NativeOnionCrawler, configured_onion_seeds


class _Response:
    status_code = 200
    headers = {"content-type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    def __init__(self, body):
        self.content = body

    async def aiter_bytes(self):
        yield self.content


class _Stream:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *args):
        return False


class _Client:
    def __init__(self, *args, **kwargs):
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, url):
        self.urls.append(url)
        if "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion" in url:
            return _Stream(_Response(b"<html><body>owned-example.com on discovered onion</body></html>"))
        if url.endswith("/"):
            return _Stream(_Response(
                b'<html><body>owned-example.com '
                b'<a href="/leak">detail</a>'
                b'<a href="https://example.com/outside">outside</a>'
                b'<a href="http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/">onion source</a>'
                b'</body></html>'
            ))
        return _Stream(_Response(b"<html><body>owned-example.com appeared</body></html>"))


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

    assert crawler.pages_checked == 3
    assert crawler.configured_seed_count == 1
    assert crawler.seed_http_status["http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"] == 200
    assert crawler.seed_content_type["http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"] == "text/html; charset=utf-8"
    assert crawler.seed_response_bytes["http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"] > 0
    assert "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/" in crawler.seed_transport_reached
    assert len(crawler.discovered_seeds) == 1
    assert crawler.seed_status["http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/"] == "checked"
    assert len(findings) == 3
    assert all(f.kind == "domain" and f.matched_value == "owned-example.com" for f in findings)
    assert all(f.metadata["exposure_layer"] == "dark" for f in findings)
    assert all(f.metadata["access_mode"] == "tor_public_onion" for f in findings)
    assert all("outside" not in (f.source_url or "") for f in findings)


@pytest.mark.asyncio
async def test_native_crawler_fails_closed_without_seed_configuration():
    crawler = NativeOnionCrawler(seeds=[], proxy="socks5://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="native_onion_missing_seeds"):
        await crawler.pull("domain", "owned-example.com")
