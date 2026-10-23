from cyclothone.darkweb.source_catalog import (
    SOURCE_CATALOG,
    get_source,
    is_excluded_source,
    reportable_as_checked,
    sources_for_layer,
)


def test_reddit_is_not_a_registered_or_reportable_source():
    assert get_source("reddit") is None
    assert is_excluded_source("reddit")
    assert is_excluded_source("community_feed", "www.reddit.com")
    assert is_excluded_source("community_feed", "redd.it")
    assert not any("reddit" in key for key in SOURCE_CATALOG)


def test_native_onion_is_dark_and_public_telegram_is_surface():
    assert get_source("native_onion").layer == "dark"
    assert get_source("telegram_public").layer == "surface"
    assert get_source("pastebin_public").layer == "surface"


def test_ransomwatch_is_live_polled_breach_intelligence_not_direct_dark_web():
    ransomwatch = get_source("ransomwatch")
    assert ransomwatch is not None
    assert ransomwatch.layer == "breach_intel"
    assert ransomwatch.access_mode == "public_feed"
    assert ransomwatch.availability == "implemented"
    assert reportable_as_checked("ransomwatch", "checked")
    assert not reportable_as_checked("ransomwatch", "failed")
    assert reportable_as_checked("native_onion", "checked")
    assert not reportable_as_checked("native_onion", "failed")
    assert not reportable_as_checked("reddit", "checked")


def test_ransomwatch_is_separate_from_native_dark_web_and_surface_sources():
    dark_ids = {source.source_id for source in sources_for_layer("dark")}
    surface_ids = {source.source_id for source in sources_for_layer("surface")}
    breach_ids = {source.source_id for source in sources_for_layer("breach_intel")}
    assert "ransomwatch" not in dark_ids
    assert "ransomwatch" not in surface_ids
    assert "ransomwatch" in breach_ids


def test_layers_are_separate_and_planned_connectors_are_explicit():
    dark_ids = {source.source_id for source in sources_for_layer("dark")}
    surface_ids = {source.source_id for source in sources_for_layer("surface")}
    assert "native_onion" in dark_ids
    assert "telegram_public" in surface_ids
    assert "pastebin_public" in surface_ids
    assert "hibp" not in surface_ids
    assert get_source("hibp") is None
    assert "bluesky_public" in surface_ids


def test_hibp_collector_is_removed_and_bluesky_collector_is_real():
    import cyclothone.darkweb.pullers as pullers

    assert not hasattr(pullers, "HIBPPuller")
    assert hasattr(pullers, "BlueskyPublicMonitor")
