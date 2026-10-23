from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.pullers import RansomwatchPuller


def test_ransomwatch_temporal_classification_separates_current_history_and_future():
    observed = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    current, current_date = RansomwatchPuller._classify_published(
        (observed - timedelta(days=2)).isoformat(), observed
    )
    historical, historical_date = RansomwatchPuller._classify_published(
        (observed - timedelta(days=45)).isoformat(), observed
    )
    future, future_date = RansomwatchPuller._classify_published(
        (observed + timedelta(days=1)).isoformat(), observed
    )

    assert current == "current_feed"
    assert current_date is not None
    assert historical == "historical_archive"
    assert historical_date is not None
    assert future == "future_dated"
    assert future_date is not None


def test_ransomwatch_undated_or_invalid_timestamps_never_become_current():
    observed = datetime.now(UTC)
    assert RansomwatchPuller._classify_published(None, observed)[0] == "historical_archive"
    assert RansomwatchPuller._classify_published("not-a-date", observed)[0] == "historical_archive"
