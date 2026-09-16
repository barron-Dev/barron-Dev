import pytest

from sentinel.web.crawler import CRED_PAIR_RE, EMAIL_RE, URL_RE, WALLET_RE, WebCrawler
from sentinel.web.orchestrator import WebIntelligenceOrchestrator


def test_indicator_extractors():
    text = "ceo@acme.example https://acme.example/login bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    assert EMAIL_RE.findall(text) == ["ceo@acme.example"]
    assert URL_RE.findall(text) == ["https://acme.example/login"]
    assert WALLET_RE.findall(text)


def test_credential_indicator_is_count_only():
    text = "admin@acme.example:Password123"
    assert len(CRED_PAIR_RE.findall(text)) == 1
    # The crawler contract exposes only a count; it never returns pair values.
    assert not hasattr(WebCrawler, "extract_credentials")


def test_layer_validation():
    WebCrawler._validate_target("https://example.com", "surface")
    WebCrawler._validate_target("https://example.com", "deep")
    WebCrawler._validate_target("http://example.onion", "dark")
    with pytest.raises(ValueError):
        WebCrawler._validate_target("http://example.onion", "surface")
    with pytest.raises(ValueError):
        WebCrawler._validate_target("https://example.com", "dark")


@pytest.mark.asyncio
async def test_deep_provider_contract_is_metadata_only(monkeypatch):
    monkeypatch.setenv("SENTINEL_INTELX_KEY", "configured")
    result = await WebIntelligenceOrchestrator().query_deep("00000000-0000-0000-0000-000000000001", "ceo@acme.example")
    assert result["configured_providers"] == ["intelx"]
    assert result["hits"] == 0
    assert "password" not in result
    assert "secret" not in result
