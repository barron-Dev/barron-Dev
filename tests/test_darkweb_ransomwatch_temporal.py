from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.pullers import RansomwatchPuller
from cyclothone.darkweb.request_worker import (
    _dedupe_temporal_candidates,
    _partition_ransomwatch_findings,
)
from cyclothone.darkweb.source_catalog import get_source


def test_ransomwatch_is_currently_polled_breach_intelligence_not_dark_web_verification():
    source = get_source("ransomwatch")
    assert source is not None
    assert source.availability == "implemented"
    assert source.layer == "breach_intel"
    assert source.access_mode == "public_feed"


def test_ransomwatch_temporal_classification_covers_current_historical_and_future():
    observed = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    assert RansomwatchPuller._classify_published(
        (observed - timedelta(days=2)).isoformat(), observed
    )[0] == "current_feed"
    assert RansomwatchPuller._classify_published(
        (observed - timedelta(days=45)).isoformat(), observed
    )[0] == "historical_archive"
    future_class, future_published = RansomwatchPuller._classify_published(
        (observed + timedelta(days=2)).isoformat(), observed
    )
    assert future_class == "future_dated"
    assert future_published is not None


def test_ransomwatch_undated_and_invalid_dates_are_historical_not_current():
    observed = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    assert RansomwatchPuller._classify_published(None, observed) == ("historical_archive", None)
    assert RansomwatchPuller._classify_published("not-a-date", observed) == ("historical_archive", None)


def test_ransomwatch_partition_requires_exact_customer_target_for_all_temporal_classes():
    from cyclothone.darkweb.pullers import Finding

    def finding(domain: str, temporal_class: str):
        return Finding(
            "ransomwatch", "domain", domain, "public aggregated feed",
            "critical", "https://example.invalid/post",
            {
                "victim_name": domain,
                "group": "example-group",
                "published": "2026-10-22T00:00:00+00:00",
                "feed_observed_at": "2026-10-23T08:00:00+00:00",
                "feed_content_sha256": "a" * 64,
                "temporal_class": temporal_class,
            },
        )

    current, historical, future = _partition_ransomwatch_findings(
        [
            finding("owned.example", "current_feed"),
            finding("owned.example", "historical_archive"),
            finding("owned.example", "future_dated"),
            finding("other.example", "current_feed"),
        ],
        "domain",
        "owned.example",
    )
    assert len(current) == 1
    assert len(historical) == 1
    assert len(future) == 1


def test_ransomwatch_temporal_candidates_deduplicate_by_stable_entry_hash():
    candidates = [
        {"entry_hash": "a" * 64, "victim_name": "owned.example", "observation_count": 1},
        {"entry_hash": "a" * 64, "victim_name": "owned.example", "observation_count": 2},
    ]
    deduped = _dedupe_temporal_candidates(candidates)
    assert len(deduped) == 1
    assert deduped[0]["observation_count"] == 2
