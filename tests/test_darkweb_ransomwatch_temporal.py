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
                "feed_freshness_verified": True,
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


def test_ransomwatch_findings_are_deduplicated_per_feed_entry_not_per_domain():
    from cyclothone.darkweb.request_worker import _tenant_finding_content_hash

    base = {
        "record_key": "a" * 64,
        "temporal_class": "current_feed",
        "published": "2026-10-22T00:00:00+00:00",
    }
    first = _tenant_finding_content_hash("ransomwatch", "owned.example", "watch-1", base)
    repeat = _tenant_finding_content_hash("ransomwatch", "owned.example", "watch-1", dict(base))
    second = _tenant_finding_content_hash(
        "ransomwatch", "owned.example", "watch-1", {**base, "record_key": "b" * 64}
    )
    assert first == repeat
    assert first != second


def test_ransomwatch_hash_fails_closed_without_stable_feed_entry_key():
    import pytest
    from cyclothone.darkweb.request_worker import _tenant_finding_content_hash

    with pytest.raises(RuntimeError, match="ransomwatch_record_key_missing"):
        _tenant_finding_content_hash("ransomwatch", "owned.example", "watch-1", {})


def test_current_ransomwatch_classification_requires_exact_tenant_row():
    import pytest
    from cyclothone.darkweb.request_worker import _require_current_breach_intel_classification

    row = {
        "id": "finding-1",
        "tenant_id": "tenant-1",
        "watchlist_id": "watch-1",
        "source_id": "ransomwatch",
        "finding_class": "current_breach_intel",
        "source_metadata": {"record_key": "a" * 64, "temporal_class": "current_feed"},
    }
    assert _require_current_breach_intel_classification(
        row, finding_id="finding-1", tenant_id="tenant-1",
        watchlist_id="watch-1", record_key="a" * 64,
    ) == row
    for field, wrong in (
        ("tenant_id", "tenant-2"),
        ("watchlist_id", "watch-2"),
        ("finding_class", "historical_archive"),
        ("id", "finding-2"),
    ):
        invalid = {**row, field: wrong}
        with pytest.raises(RuntimeError, match="ransomwatch_current_classification_unconfirmed"):
            _require_current_breach_intel_classification(
                invalid, finding_id="finding-1", tenant_id="tenant-1",
                watchlist_id="watch-1", record_key="a" * 64,
            )


def test_current_ransomwatch_finding_requires_this_request_binding():
    from cyclothone.darkweb.request_worker import _is_current_finding

    row = {
        "source_id": "ransomwatch",
        "source_metadata": {
            "temporal_class": "current_feed",
            "feed_freshness_verified": True,
            "feed_observed_at": datetime.now(UTC).isoformat(),
            "published": datetime.now(UTC).isoformat(),
        },
    }
    assert not _is_current_finding(row, "request-1")
    row["source_metadata"]["service_request_id"] = "request-2"
    assert not _is_current_finding(row, "request-1")
    row["source_metadata"]["service_request_id"] = "request-1"
    assert _is_current_finding(row, "request-1")
