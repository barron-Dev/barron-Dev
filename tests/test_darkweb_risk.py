from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.risk import ALERT_THRESHOLD, assess_finding


def test_high_confidence_exact_match_can_be_alert_eligible():
    result = assess_finding(
        {
            "source_id": "hibp",
            "kind": "email",
            "severity": "high",
            "metadata": {"published": "2026-10-10T10:00:00Z"},
        },
        target_matched=True,
        now=datetime(2026, 10, 10, 11, tzinfo=UTC),
    )

    assert result["risk_score"] >= ALERT_THRESHOLD
    assert result["alert_eligible"] is True
    assert any(item["factor"] == "exact_authorized_watchlist_match" for item in result["risk_factors"])
    assert "not a probability" in result["score_semantics"]


def test_unmatched_detection_never_becomes_alert_eligible():
    result = assess_finding(
        {"source_id": "unknown_feed", "kind": "company_name", "severity": "critical", "metadata": {}},
        target_matched=False,
    )

    assert result["alert_eligible"] is False
    assert result["risk_score"] <= 0.99
    assert result["risk_factors"][-1]["value"] is False


def test_old_evidence_scores_below_equivalent_recent_evidence():
    now = datetime(2026, 10, 10, tzinfo=UTC)
    base = {"source_id": "hibp", "kind": "email", "severity": "high"}
    recent = assess_finding(
        {**base, "metadata": {"published": (now - timedelta(hours=4)).isoformat()}},
        target_matched=True,
        now=now,
    )
    old = assess_finding(
        {**base, "metadata": {"published": (now - timedelta(days=90)).isoformat()}},
        target_matched=True,
        now=now,
    )

    assert recent["risk_score"] > old["risk_score"]


def test_invalid_publication_time_does_not_inflate_score():
    result = assess_finding(
        {
            "source_id": "unknown_feed",
            "kind": "company_name",
            "severity": "medium",
            "metadata": {"published": "not-a-date"},
        },
        target_matched=True,
    )

    assert result["risk_score"] < ALERT_THRESHOLD
    assert result["alert_eligible"] is False



def test_future_publication_time_does_not_receive_freshness_bonus():
    now = datetime(2026, 10, 10, tzinfo=UTC)
    result = assess_finding(
        {
            "source_id": "unknown_feed",
            "kind": "company_name",
            "severity": "medium",
            "metadata": {"published": (now + timedelta(days=5)).isoformat()},
        },
        target_matched=True,
        now=now,
    )

    freshness = next(item for item in result["risk_factors"] if item["factor"] == "freshness")
    assert freshness["contribution"] == 0.0
    assert freshness["value"] == "publication_time_in_future"
