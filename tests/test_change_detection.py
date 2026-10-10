from datetime import UTC, datetime, timedelta

import pytest

from cyclothone.streaming.change_detection import build_change_event, score_change


def test_scoring_formula_routes_immediate_events():
    score, tier = score_change(
        event_type="STEALER_LOG_APPEARANCE",
        relevance="EXACT",
        source_reliability=10,
        freshness=10,
    )
    assert score == 10.0
    assert tier == "immediate"


def test_scoring_formula_routes_scheduled_and_archive():
    score, tier = score_change(
        event_type="PROFILE_MODIFICATION",
        relevance="OTHER",
        source_reliability=3,
        freshness=1,
    )
    assert score < 4
    assert tier == "archive"


def test_event_is_deterministic_and_does_not_store_raw_identifier():
    finding = {
        "source_id": "hibp",
        "kind": "email",
        "matched_value": "person@example.com",
        "context": "reported breach",
        "severity": "high",
        "source_url": "https://example.com/report?token=secret#details",
        "metadata": {"published": "2026-10-10T10:00:00Z"},
    }
    now = datetime(2026, 10, 10, 10, 30, tzinfo=UTC)
    first = build_change_event(finding, collected_at=now)
    second = build_change_event(finding, collected_at=now)
    assert first["event_id"] == second["event_id"]
    assert first["subject_id"] != "person@example.com"
    assert "person@example.com" not in str(first)
    assert "token=secret" not in str(first)
    assert first["source_url"] == "https://example.com/report"
    assert len(first["raw_payload_hash"]) == 64


def test_undated_observation_is_not_assumed_fresh():
    event = build_change_event(
        {
            "source_id": "unknown_public_feed",
            "kind": "company_name",
            "matched_value": "Example Ltd",
            "metadata": {},
        },
        collected_at=datetime(2026, 10, 10, tzinfo=UTC),
    )
    assert event["change_details"]["freshness_score"] == 1


def test_lookalike_taxonomy_values_are_rejected():
    with pytest.raises(ValueError, match="unsupported_change_type"):
        score_change(event_type="UNRECOGNIZED", relevance="EXACT", source_reliability=5, freshness=5)
