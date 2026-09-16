from datetime import UTC, datetime, timedelta

from sentinel.compliance.assurance import AssuranceEngine


def test_type2_requires_closed_period():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 6, 1, tzinfo=UTC)
    now = datetime(2026, 9, 1, tzinfo=UTC)
    assert AssuranceEngine.period_mode("type2", start, end, now) == "operating_period_complete"
    assert AssuranceEngine.period_mode("type2", start, datetime(2026, 10, 1, tzinfo=UTC), now) == "operating_period_open"


def test_type1_is_point_in_time():
    start = datetime(2026, 8, 1, tzinfo=UTC)
    end = datetime(2026, 8, 2, tzinfo=UTC)
    assert AssuranceEngine.period_mode("type1", start, end, datetime(2026, 9, 1, tzinfo=UTC)) == "point_in_time"


def test_observation_tracks_first_and_last_seen_and_coverage():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 2, 1, tzinfo=UTC)
    items = [
        {"control_id": "c1", "collected_at": "2026-01-03T00:00:00+00:00", "valid_until": "2026-02-02T00:00:00+00:00"},
        {"control_id": "c1", "collected_at": "2026-01-20T00:00:00+00:00", "valid_until": "2026-02-19T00:00:00+00:00"},
    ]
    results = [
        {"control_id": "c1", "source_ref": "audit_log", "status": "collected", "stale": False},
        {"control_id": "c1", "source_ref": "devices", "status": "collected", "stale": False},
    ]
    controls = [{"id": "c1", "evidence_sources": ["audit_log", "devices"]}]
    observations = AssuranceEngine.observations(
        controls, items, results, start, end,
        now=datetime(2026, 1, 25, tzinfo=UTC),
    )
    assert observations[0].first_seen == datetime(2026, 1, 3, tzinfo=UTC)
    assert observations[0].last_seen == datetime(2026, 1, 20, tzinfo=UTC)
    assert observations[0].evidence_count == 2
    assert observations[0].coverage == 1.0
    assert observations[0].operating_effectiveness == "observed"


def test_missing_source_is_insufficient_evidence():
    controls = [{"id": "c1", "evidence_sources": ["audit_log", "devices"]}]
    results = [{"control_id": "c1", "source_ref": "audit_log", "status": "collected", "stale": False}]
    observations = AssuranceEngine.observations(
        controls,
        [{"control_id": "c1", "collected_at": "2026-01-10T00:00:00Z", "valid_until": "2026-02-10T00:00:00Z"}],
        results,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 2, 1, tzinfo=UTC),
        now=datetime(2026, 1, 20, tzinfo=UTC),
    )
    assert observations[0].coverage == 0.5
    assert observations[0].operating_effectiveness == "partial_coverage"
