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


def test_global_ransomwatch_alert_pipeline_quarantines_historical_and_future_rows():
    from cyclothone.darkweb.pullers import Finding
    from cyclothone.darkweb.scheduler import _current_ransomwatch_findings

    def row(temporal_class):
        return Finding(
            "ransomwatch", "company_name", "example victim", "feed", "critical",
            "https://feed.example/post", {"temporal_class": temporal_class},
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

        async def get(self, url):
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
    assert record["victim_name"] == "Example Corporation"
    assert findings
