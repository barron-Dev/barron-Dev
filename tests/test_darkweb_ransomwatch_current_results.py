import pytest

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


@pytest.mark.asyncio
async def test_persisted_ransomwatch_history_is_target_scoped_and_keeps_future_quarantined(monkeypatch):
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _load_persisted_ransomwatch_candidates

    rows = [
        {
            "entry_hash": "a" * 64, "temporal_class": "historical_archive",
            "published_at": "2026-08-01T00:00:00+00:00",
            "feed_observed_at": "2026-10-23T00:00:00+00:00",
            "feed_content_sha256": "b" * 64, "victim_name": "example corporation",
            "group_name": "group-a", "source_url": "https://feed.invalid/old",
            "label": "historical", "match_kind": "domain", "matched_value": "example.com",
            "last_seen_at": "2026-10-23T00:00:00+00:00", "observation_count": 2,
        },
        {
            "entry_hash": "c" * 64, "temporal_class": "future_dated",
            "published_at": "2026-10-24T00:00:00+00:00",
            "feed_observed_at": "2026-10-23T00:00:00+00:00",
            "feed_content_sha256": "d" * 64, "victim_name": "example corporation",
            "group_name": "group-b", "source_url": "https://feed.invalid/future",
            "label": "future", "match_kind": "domain", "matched_value": "example.com",
            "last_seen_at": "2026-10-23T00:00:00+00:00", "observation_count": 1,
        },
        {
            "entry_hash": "e" * 64, "temporal_class": "historical_archive",
            "published_at": "2026-08-01T00:00:00+00:00",
            "feed_observed_at": "2026-10-23T00:00:00+00:00",
            "feed_content_sha256": "f" * 64, "victim_name": "other corporation",
            "group_name": "group-c", "source_url": "https://feed.invalid/other",
            "label": "wrong target", "match_kind": "domain", "matched_value": "other.example",
            "last_seen_at": "2026-10-23T00:00:00+00:00", "observation_count": 1,
        },
    ]

    class Query:
        def select(self, columns):
            return self
        def match(self, filters):
            assert filters == {
                "tenant_id": "tenant-1",
                "watchlist_id": "watch-1",
                "source_id": "ransomwatch",
            }
            return self
        def order(self, *args, **kwargs):
            return self
        def limit(self, value):
            assert value == 1000
            return self
        async def execute(self):
            return SimpleNamespace(data=rows)

    class Client:
        def table(self, table):
            assert table == "dw_feed_temporal_observations"
            return Query()

    class Supabase:
        async def _ensure(self):
            return Client()

    monkeypatch.setattr("cyclothone.darkweb.request_worker.supabase", Supabase())
    historical, future, status = await _load_persisted_ransomwatch_candidates(
        "tenant-1", "watch-1", "domain", "example.com"
    )
    assert len(historical) == 1
    assert len(future) == 1
    assert historical[0]["entry_hash"] == "a" * 64
    assert future[0]["temporal_class"] == "future_dated"
    assert future[0]["direct_onion_access_verified"] is False
    assert status["state"] == "checked"
