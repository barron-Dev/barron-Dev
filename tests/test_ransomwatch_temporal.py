from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.pullers import Finding, RansomwatchPuller
from cyclothone.darkweb.request_worker import _partition_ransomwatch_findings


def _finding(kind: str, value: str, temporal_class: str, published: str | None) -> Finding:
    return Finding(
        source_id="ransomwatch",
        kind=kind,
        matched_value=value,
        context="Public Ransomwatch feed record; not direct onion verification.",
        severity="critical",
        source_url="https://example.invalid/post",
        metadata={
            "temporal_class": temporal_class,
            "published": published,
            "feed_observed_at": "2026-10-23T00:00:00+00:00",
            "victim_name": "Example Corporation",
            "group": "example-group",
            "direct_onion_access_verified": False,
        },
    )


def test_ransomwatch_classifies_current_historical_and_future_dates():
    observed = datetime(2026, 10, 23, tzinfo=UTC)
    assert RansomwatchPuller._classify_published(
        (observed - timedelta(days=2)).isoformat(), observed
    )[0] == "current_feed"
    assert RansomwatchPuller._classify_published(
        (observed - timedelta(days=45)).isoformat(), observed
    )[0] == "historical_archive"
    assert RansomwatchPuller._classify_published(
        (observed + timedelta(days=1)).isoformat(), observed
    )[0] == "future_dated"
    assert RansomwatchPuller._classify_published("", observed) == ("historical_archive", None)


def test_ransomwatch_partitions_temporal_classes_and_never_alerts_future_or_archive():
    current = _finding("domain", "example.com", "current_feed", "2026-10-22T00:00:00+00:00")
    historical = _finding("domain", "example.com", "historical_archive", "2026-08-01T00:00:00+00:00")
    future = _finding("domain", "example.com", "future_dated", "2026-10-24T00:00:00+00:00")

    live, archived, quarantined = _partition_ransomwatch_findings(
        [current, historical, future], "domain", "example.com"
    )
    assert live == [current]
    assert len(archived) == 1 and archived[0]["temporal_class"] == "historical_archive"
    assert len(quarantined) == 1 and quarantined[0]["temporal_class"] == "future_dated"


def test_ransomwatch_exact_matching_supports_brand_and_url_host_without_fuzzy_matches():
    current_brand = _finding("company_name", "Example Corporation", "current_feed", "2026-10-22T00:00:00+00:00")
    current_domain = _finding("domain", "example.com", "current_feed", "2026-10-22T00:00:00+00:00")
    wrong_domain = _finding("domain", "notexample.com", "current_feed", "2026-10-22T00:00:00+00:00")

    live_brand, _, _ = _partition_ransomwatch_findings(
        [current_brand], "brand", "Example Corporation"
    )
    live_url, _, _ = _partition_ransomwatch_findings(
        [current_domain, wrong_domain], "url", "https://example.com/login"
    )
    assert live_brand == [current_brand]
    assert live_url == [current_domain]


def test_ransomwatch_is_an_implemented_feed_not_a_historical_only_provider():
    from cyclothone.darkweb.source_catalog import get_source

    source = get_source("ransomwatch")
    assert source is not None
    assert source.availability == "implemented"
    assert source.layer == "breach_intel"
    assert source.access_mode == "public_feed"
