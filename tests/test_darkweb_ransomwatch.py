import pytest

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

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


def test_ransomwatch_current_hits_are_separated_from_history_and_future():
    from cyclothone.darkweb.pullers import Finding
    from cyclothone.darkweb.request_worker import _partition_ransomwatch_findings

    def finding(temporal_class):
        return Finding(
            "ransomwatch", "domain", "victim.example", "feed entry", "critical",
            "https://feed.example/post",
            {
                "temporal_class": temporal_class,
                "published": "2026-10-23T00:00:00+00:00",
                "feed_observed_at": "2026-10-23T08:00:00+00:00",
                "victim_name": "victim.example",
                "group": "test-group",
            },
        )

    current, historical, future = _partition_ransomwatch_findings(
        [finding("current_feed"), finding("historical_archive"), finding("future_dated")],
        "domain",
        "victim.example",
    )
    assert len(current) == 1
    assert len(historical) == 1
    assert len(future) == 1
    assert historical[0]["label"].startswith("historical feed match")
    assert future[0]["label"].startswith("future-dated feed entry")
    assert len(historical[0]["entry_hash"]) == 64
    assert len(future[0]["entry_hash"]) == 64


def test_global_ransomwatch_alert_pipeline_quarantines_historical_and_future_rows():
    from cyclothone.darkweb.pullers import Finding
    from cyclothone.darkweb.scheduler import _current_ransomwatch_findings

    def row(temporal_class):
        return Finding(
            "ransomwatch", "company_name", "example victim", "feed", "critical",
            "https://feed.example/post", {"temporal_class": temporal_class, "feed_freshness_verified": temporal_class == "current_feed"},
        )

    current = row("current_feed")
    result = _current_ransomwatch_findings([
        current, row("historical_archive"), row("future_dated"), row("unknown"),
    ])
    assert result == [current]


@pytest.mark.asyncio
async def test_ransomwatch_pull_emits_durable_temporal_record(monkeypatch):
    import json
    from datetime import UTC, datetime, timedelta
    from cyclothone.darkweb.pullers import RansomwatchPuller

    post = {
        "post_title": "Example Corporation",
        "post_url": "https://example.invalid/post",
        "group_name": "group-a",
        "discovered": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
    }
    body = json.dumps([post]).encode()

    class Response:
        content = body
        headers = {"date": format_datetime(datetime.now(UTC)), "age": "0"}

        def raise_for_status(self):
            return None

        def json(self):
            return [post]

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            assert url == RansomwatchPuller.FEED
            return Response()

    monkeypatch.setattr("cyclothone.darkweb.pullers.httpx.AsyncClient", Client)
    puller = RansomwatchPuller()
    findings = await puller.pull()

    assert puller.feed_checked is True
    assert len(puller.temporal_records) == 1
    record = puller.temporal_records[0]
    assert len(record["record_key"]) == 64
    assert record["temporal_class"] == "current_feed"
    assert record["feed_content_sha256"] == __import__("hashlib").sha256(body).hexdigest()
    assert record["victim_name"] == "example corporation"
    assert findings



def test_ransomwatch_tolerates_only_bounded_future_clock_skew():
    observed = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    near_future, _ = RansomwatchPuller._classify_published(
        (observed + timedelta(minutes=2)).isoformat(), observed
    )
    beyond_tolerance, _ = RansomwatchPuller._classify_published(
        (observed + timedelta(minutes=6)).isoformat(), observed
    )
    assert near_future == "current_feed"
    assert beyond_tolerance == "future_dated"


def test_temporal_candidates_deduplicate_stable_feed_entry_hash():
    from cyclothone.darkweb.request_worker import _dedupe_temporal_candidates

    key = "a" * 64
    older = {"entry_hash": key, "victim_name": "Example", "observation_count": 1}
    latest = {"entry_hash": key, "victim_name": "Example", "observation_count": 2}
    other = {"entry_hash": "b" * 64, "victim_name": "Other"}
    result = _dedupe_temporal_candidates([older, latest, other])
    assert result == [latest, other]



@pytest.mark.asyncio
async def test_ransomwatch_retains_current_historical_and_future_metadata(monkeypatch):
    import json

    now = datetime.now(UTC)
    posts = [
        {
            "post_title": "Current Example",
            "post_url": "https://feed.example/current",
            "group_name": "group-a",
            "discovered": (now - timedelta(days=1)).isoformat(),
        },
        {
            "post_title": "Historical Example",
            "post_url": "https://feed.example/historical",
            "group_name": "group-b",
            "discovered": (now - timedelta(days=60)).isoformat(),
        },
        {
            "post_title": "Future Example",
            "post_url": "https://feed.example/future",
            "group_name": "group-c",
            "discovered": (now + timedelta(days=1)).isoformat(),
        },
    ]
    body = json.dumps(posts).encode()

    class Response:
        content = body
        headers = {"date": format_datetime(datetime.now(UTC)), "age": "0"}
        def raise_for_status(self):
            return None
        def json(self):
            return posts

    class Client:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False
        async def get(self, url):
            return Response()

    monkeypatch.setattr("cyclothone.darkweb.pullers.httpx.AsyncClient", Client)
    puller = RansomwatchPuller()
    await puller.pull()
    classes = {record["temporal_class"] for record in puller.temporal_records}
    assert classes == {"current_feed", "historical_archive", "future_dated"}
    assert all(len(record["record_key"]) == 64 for record in puller.temporal_records)
    assert all(record["feed_content_sha256"] for record in puller.temporal_records)
