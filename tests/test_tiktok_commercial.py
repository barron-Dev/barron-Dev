import pytest

from cyclothone.darkweb.tiktok import TikTokCommercialContentMonitor


def test_tiktok_domain_match_is_exact() -> None:
    match = TikTokCommercialContentMonitor._matches_target(
        "domain", "example.com", "Advertiser: example.com", "Acme"
    )
    nonmatch = TikTokCommercialContentMonitor._matches_target(
        "domain", "example.com", "Advertiser: example.com.attacker.invalid", "Acme"
    )
    assert match is True
    assert nonmatch is False


def test_tiktok_brand_match_is_phrase_exact() -> None:
    assert TikTokCommercialContentMonitor._matches_target(
        "company_name", "chara enterprise", "Chara Enterprise campaign", "Chara Enterprise"
    )
    assert not TikTokCommercialContentMonitor._matches_target(
        "company_name", "chara enterprise", "Chara Enterprises campaign", "Other"
    )


def test_tiktok_username_requires_exact_handle_or_at_mention() -> None:
    assert TikTokCommercialContentMonitor._matches_target(
        "username", "sample_user", "Promotion", "sample_user"
    )
    assert TikTokCommercialContentMonitor._matches_target(
        "username", "sample_user", "Mentioned @sample_user today", "Other"
    )
    assert not TikTokCommercialContentMonitor._matches_target(
        "username", "sample_user", "Mentioned sample_user today", "Other"
    )


@pytest.mark.asyncio
async def test_tiktok_source_fails_closed_without_approved_credentials() -> None:
    monitor = TikTokCommercialContentMonitor(client_key="", client_secret="")
    with pytest.raises(RuntimeError, match="credentials_required"):
        await monitor.pull_target("company_name", "example brand")
