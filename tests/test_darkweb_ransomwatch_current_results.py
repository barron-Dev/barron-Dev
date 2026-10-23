from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.request_worker import _is_current_finding


def test_current_ransomwatch_feed_record_is_current_when_fresh_and_tenant_scoped():
    now = datetime.now(UTC)
    row = {
        "source_id": "ransomwatch",
        "finding_class": "historical_archive",
        "source_metadata": {
            "temporal_class": "current_feed",
            "feed_observed_at": now.isoformat(),
            "published": (now - timedelta(days=2)).isoformat(),
            "service_request_id": "request-1",
        },
    }
    assert _is_current_finding(row, "request-1")
    assert not _is_current_finding(row, "request-2")


def test_historical_future_dated_and_stale_ransomwatch_records_are_not_current():
    now = datetime.now(UTC)
    base = {
        "source_id": "ransomwatch",
        "finding_class": "historical_archive",
        "source_metadata": {
            "feed_observed_at": now.isoformat(),
            "published": (now - timedelta(days=2)).isoformat(),
        },
    }
    for temporal_class in ("historical_archive", "future_dated"):
        row = {**base, "source_metadata": {**base["source_metadata"], "temporal_class": temporal_class}}
        assert not _is_current_finding(row, "request-1")

    stale = {
        **base,
        "source_metadata": {
            **base["source_metadata"],
            "temporal_class": "current_feed",
            "feed_observed_at": (now - timedelta(hours=2)).isoformat(),
        },
    }
    assert not _is_current_finding(stale, "request-1")
