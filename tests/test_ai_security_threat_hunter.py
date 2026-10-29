import pytest
from cyclothone.ai_security.threat_hunter import EvidenceRef, AgentHypothesis, adjudicate_evidence


def ev(i, source, tenant="t", verified=True, coverage="complete"):
    return EvidenceRef(i, tenant, source, str(i)*64, verified, "2026-10-29T00:00:00Z", coverage)


def test_independent_verified_evidence_can_be_sent_for_review():
    result = adjudicate_evidence(tenant_id="t", evidence=(ev("a","watchtower"),ev("b","darkweb")),
        hypotheses=(AgentHypothesis("skeptic","challenge","possible benign event",("a",)),
                    AgentHypothesis("auditor","support","evidence suggests concern",("a","b"))))
    assert result["disposition"] == "human_review_required"
    assert result["automatic_enforcement_permitted"] is False


def test_opinion_text_never_substitutes_for_evidence():
    result = adjudicate_evidence(tenant_id="t", evidence=(),
        hypotheses=(AgentHypothesis("auditor","support","CRITICAL_THREAT",()),))
    assert result["disposition"] == "insufficient_evidence"


def test_cross_tenant_evidence_rejected():
    with pytest.raises(ValueError, match="cross_tenant_evidence"):
        adjudicate_evidence(tenant_id="t", evidence=(ev("a","watchtower","other"),), hypotheses=())


def test_missing_or_unverified_source_forces_review():
    result = adjudicate_evidence(tenant_id="t", evidence=(ev("a","watchtower",verified=False),),
        hypotheses=(AgentHypothesis("auditor","support","claim",("a",)),))
    assert result["disposition"] == "insufficient_evidence"
    assert result["coverage_gaps"]
