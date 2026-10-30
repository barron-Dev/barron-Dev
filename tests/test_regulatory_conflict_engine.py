from datetime import datetime, timedelta, timezone

import pytest

from cyclothone.compliance.conflict_engine import (
    EvidenceContext, RetentionObligation, evaluate_lifecycle_request,
)

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def evidence(**overrides):
    values = dict(
        tenant_id="tenant-a", evidence_id="evidence-1", evidence_sha256="a" * 64,
        jurisdiction="EU", evidence_class="security_incident",
        collected_at=NOW - timedelta(days=2), attributes={"sector": "financial"},
    )
    values.update(overrides)
    return EvidenceContext(**values)


def obligation(**overrides):
    values = dict(
        obligation_key="eu-retention-1", source_citation="Reviewed authority citation",
        source_version="2026-10", jurisdiction="EU", evidence_class="security_incident",
        effective_from=NOW - timedelta(days=100), effective_until=None, reviewed=True,
        applicability={"sector": "financial"}, required_actions=("retain", "restrict_access"),
        source_digest="b" * 64, freshness_deadline=NOW + timedelta(days=30),
    )
    values.update(overrides)
    return RetentionObligation(**values)


def test_delete_conflicting_with_retention_is_not_authorized():
    result = evaluate_lifecycle_request(evidence(), [obligation()], "delete", now=NOW)
    assert result.state == "conflict_detected"
    assert result.conflicts[0].reason_code == "requested_action_not_permitted_by_obligation"


def test_unknown_applicability_blocks():
    item = obligation(applicability={"sector": "financial", "activity": "payments"})
    result = evaluate_lifecycle_request(evidence(), [item], "delete", now=NOW)
    assert result.state == "applicability_unknown"
    assert "eu-retention-1" in result.unknown_obligations


def test_stale_source_blocks():
    item = obligation(freshness_deadline=NOW - timedelta(seconds=1))
    result = evaluate_lifecycle_request(evidence(), [item], "delete", now=NOW)
    assert result.state == "applicability_unknown"
    assert "obligation_source_stale" in result.reason_codes


def test_unreviewed_source_blocks():
    result = evaluate_lifecycle_request(evidence(), [obligation(reviewed=False)], "delete", now=NOW)
    assert result.state == "applicability_unknown"
    assert "obligation_not_legally_reviewed" in result.reason_codes


def test_no_obligation_data_never_authorizes_deletion():
    result = evaluate_lifecycle_request(evidence(), [], "delete", now=NOW)
    assert result.state == "applicability_unknown"
    assert "no_applicable_obligation_data" in result.reason_codes


def test_permitted_action_has_no_conflict():
    result = evaluate_lifecycle_request(
        evidence(), [obligation(required_actions=("delete", "retain"))], "delete", now=NOW
    )
    assert result.state == "no_conflict"


def test_digest_and_timezone_are_strict():
    with pytest.raises(ValueError, match="lowercase_sha256"):
        evaluate_lifecycle_request(evidence(evidence_sha256="not-a-digest"), [obligation()], "delete", now=NOW)
    with pytest.raises(ValueError, match="naive_datetime"):
        evaluate_lifecycle_request(evidence(), [obligation()], "delete", now=datetime(2026, 10, 27))


def test_snapshot_digest_is_deterministic():
    a = evaluate_lifecycle_request(evidence(), [obligation()], "delete", now=NOW)
    b = evaluate_lifecycle_request(evidence(), [obligation()], "delete", now=NOW)
    assert a.snapshot_sha256 == b.snapshot_sha256


def test_unreviewed_obligation_for_another_jurisdiction_does_not_poison_evaluation():
    unrelated = obligation(jurisdiction="US", reviewed=False)
    result = evaluate_lifecycle_request(
        evidence(), [unrelated, obligation(required_actions=("delete", "retain"))], "delete", now=NOW
    )
    assert result.state == "no_conflict"
    assert result.matched_obligations == ("eu-retention-1",)


def test_reviewed_obligation_without_source_digest_blocks():
    result = evaluate_lifecycle_request(evidence(), [obligation(source_digest=None)], "delete", now=NOW)
    assert result.state == "applicability_unknown"
    assert "obligation_source_digest_missing_or_invalid" in result.reason_codes


def test_snapshot_digest_binds_obligation_version_and_source():
    first = evaluate_lifecycle_request(evidence(), [obligation(source_version="2026-10")], "delete", now=NOW)
    second = evaluate_lifecycle_request(evidence(), [obligation(source_version="2026-11")], "delete", now=NOW)
    assert first.snapshot_sha256 != second.snapshot_sha256
