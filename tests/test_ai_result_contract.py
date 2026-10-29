import pytest

from cyclothone.ai.result_contract import ResultContract, SourceOutcome


def test_partial_coverage_is_explicit_and_serializable():
    contract = ResultContract(
        request_id="req-1",
        status="partial_coverage",
        sources=(
            SourceOutcome("primary", "succeeded", evidence_count=2),
            SourceOutcome("secondary", "unavailable", reason_code="source_unavailable"),
        ),
        result={"finding_count": 2},
    )
    data = contract.to_dict()
    assert data["status"] == "partial_coverage"
    assert data["sources"][1]["status"] == "unavailable"
    assert data["sources"][1]["reason_code"] == "source_unavailable"


def test_complete_cannot_hide_unavailable_source():
    with pytest.raises(ValueError, match="complete_result_cannot_hide"):
        ResultContract(
            "req-1", "complete",
            (
                SourceOutcome("primary", "succeeded"),
                SourceOutcome("secondary", "unavailable", reason_code="offline"),
            ),
            {"finding_count": 0},
        )


def test_partial_coverage_requires_a_real_incomplete_source():
    with pytest.raises(ValueError, match="partial_coverage_requires"):
        ResultContract(
            "req-1", "partial_coverage",
            (SourceOutcome("primary", "succeeded"),), {},
        )


def test_blocked_result_cannot_claim_results():
    with pytest.raises(ValueError, match="blocked_result_must_not_claim"):
        ResultContract(
            "req-1", "blocked",
            (SourceOutcome("primary", "blocked", reason_code="policy_denied"),),
            {"finding_count": 1},
        )


def test_unknown_statuses_are_rejected():
    with pytest.raises(ValueError, match="invalid_source_status"):
        SourceOutcome("source", "clean")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid_overall_status"):
        ResultContract("req-1", "clean", (SourceOutcome("source", "succeeded"),), {})  # type: ignore[arg-type]
