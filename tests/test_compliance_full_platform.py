from datetime import UTC, datetime, timedelta

from sentinel.compliance.gap import GapAnalyzer
from sentinel.compliance.scoring import ComplianceScorer
from sentinel.compliance.vendor_risk import VendorRiskScorer


def test_scoring_excludes_not_applicable():
    result = ComplianceScorer().score([{"id": "a", "category": "access"}, {"id": "b", "category": "governance"}], {"a": {"status": "passing"}, "b": {"status": "not_applicable"}})
    assert result.total == 1
    assert result.score == 1.0


def test_scoring_exception_is_readiness_credit_not_full_pass():
    result = ComplianceScorer().score([{"id": "a", "category": "access"}], {"a": {"status": "failing"}}, {"a": {"status": "remediating"}})
    assert result.score == 0.7
    assert result.failing == 1


def test_gap_prioritizes_cross_framework_controls():
    gaps = GapAnalyzer().analyze([{"id": "a", "code": "CC6.1", "title": "Access", "category": "access", "framework": "soc2"}], {"a": {"status": "unknown"}}, {"a": {"soc2", "iso27001", "gdpr"}})
    assert gaps[0].severity == "high"
    assert gaps[0].framework_count == 3


def test_vendor_risk_requires_data_class_controls():
    result = VendorRiskScorer().score({"criticality": "high", "data_access": ["pii"], "gdpr": False, "soc2": True})
    assert result.score < 1.0
    assert any("missing compliance evidence" in reason for reason in result.reasons)


def test_vendor_review_overdue_reduces_score():
    now = datetime(2026, 9, 16, tzinfo=UTC)
    result = VendorRiskScorer().score({"criticality": "medium", "data_access": [], "report_urls": ["internal"], "next_review_at": (now - timedelta(days=40)).isoformat()}, now=now)
    assert result.score < 1.0
    assert any("overdue" in reason for reason in result.reasons)
