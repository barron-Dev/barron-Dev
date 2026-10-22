from unittest.mock import patch

import pytest

from cyclothone.darkweb.native_onion import MAX_BODY_BYTES, NativeOnionCrawler, configured_onion_seeds


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
    last_urls = []

    def __init__(self, *args, **kwargs):
        self.urls = []
        type(self).last_urls = self.urls

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
            "https://example.com/,https://short.onion/,http://user:pass@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/"
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
    assert crawler.configured_seed_count == 1
    assert len(crawler.discovered_seeds) == 1
    discovered_url = crawler.discovered_seeds[0]["url"]
    assert discovered_url.endswith("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/")
    assert discovered_url not in crawler.seed_status
    assert not any("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion" in url for url in _Client.last_urls)
    assert len(findings) == 2
    assert all(f.kind == "domain" and f.matched_value == "owned-example.com" for f in findings)
    assert all(f.metadata["exposure_layer"] == "dark" for f in findings)
    assert all(f.metadata["access_mode"] == "tor_public_onion" for f in findings)
    assert all("outside" not in (f.source_url or "") for f in findings)


@pytest.mark.asyncio
async def test_native_crawler_rejects_oversized_response_without_hashing_partial_body():
    class _LargeClient(_Client):
        def stream(self, method, url):
            self.urls.append(url)
            return _Stream(_Response(b"x" * (MAX_BODY_BYTES + 1)))

    seed = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"
    crawler = NativeOnionCrawler(seeds=[seed], proxy="socks5://127.0.0.1:9050")
    with patch("cyclothone.darkweb.native_onion.httpx.AsyncClient", _LargeClient):
        with pytest.raises(RuntimeError, match="native_onion_no_seed_reachable"):
            await crawler.pull("domain", "owned-example.com")

    evidence = crawler.seed_probe_evidence[seed]
    assert evidence["http_status"] == 200
    assert evidence["error_code"] == "response_body_too_large"
    assert evidence["response_sha256"] is None
    assert crawler.pages_checked == 0


@pytest.mark.asyncio
async def test_native_crawler_fails_closed_without_seed_configuration():
    crawler = NativeOnionCrawler(seeds=[], proxy="socks5://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="native_onion_missing_seeds"):
        await crawler.pull("domain", "owned-example.com")



def test_native_target_matcher_rejects_empty_normalized_value():
    from cyclothone.darkweb.native_onion import _target_pattern

    with pytest.raises(ValueError, match="native_onion_empty_normalized_target"):
        _target_pattern("domain", " \t ")


def test_native_target_matcher_uses_domain_boundaries():
    from cyclothone.darkweb.native_onion import _target_pattern

    pattern = _target_pattern("domain", "owned-example.com")
    assert pattern.search("the domain owned-example.com was listed")
    assert not pattern.search("notowned-example.com")
    assert not pattern.search("owned-example.com.attacker.invalid")


def test_native_target_matcher_rejects_unsupported_target_kind():
    from cyclothone.darkweb.native_onion import _target_pattern

    with pytest.raises(ValueError, match="native_onion_unsupported_target_kind"):
        _target_pattern("unexpected_kind", "target-value")



def test_native_evidence_excerpt_preserves_target_and_redacts_secrets():
    from cyclothone.darkweb.native_onion import _target_pattern, sanitize_target_matched_excerpt

    page = (
        "owned-example.com was listed. "
        "password=supersecret-value api_key=ABCDEFGHIJKLMNOPQRSTUVWX123456 "
        "contact victim@example.net "
        "jwt=eyJabcdefghijk.abcdefghijk.abcdefghijk "
        "AKIA1234567890ABCDEF"
    )
    excerpt = sanitize_target_matched_excerpt(page, _target_pattern("domain", "owned-example.com"))
    assert excerpt is not None
    assert "owned-example.com" in excerpt
    assert "supersecret-value" not in excerpt
    assert "ABCDEFGHIJKLMNOPQRSTUVWX123456" not in excerpt
    assert "victim@example.net" not in excerpt
    assert "eyJabcdefghijk.abcdefghijk.abcdefghijk" not in excerpt
    assert "AKIA1234567890ABCDEF" not in excerpt


def test_native_evidence_excerpt_returns_none_without_exact_target():
    from cyclothone.darkweb.native_onion import _target_pattern, sanitize_target_matched_excerpt

    assert sanitize_target_matched_excerpt(
        "attacker-owned-example.com.attacker.invalid",
        _target_pattern("domain", "owned-example.com"),
    ) is None
