from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cyclothone.developer.result_contract import (
    CoverageReceipt,
    IntegrityState,
    ResultContract,
    ResultDisposition,
    ServiceTaskReceipt,
    TaskOutcome,
)


NOW = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)


def task(task_id: str, outcome: TaskOutcome, attempted: bool = True) -> ServiceTaskReceipt:
    return ServiceTaskReceipt(
        task_id=task_id,
        service_id="darkweb.exposure",
        outcome=outcome,
        attempted_at=NOW if attempted else None,
        completed_at=NOW if attempted else None,
        source_attempt_count=1 if attempted else 0,
    )


def base_result(**overrides) -> dict:
    result = {
        "result_id": "result-1",
        "session_id": "session-1",
        "tenant_id": "tenant-1",
        "asset_id": "asset-1",
        "generated_at": NOW,
        "disposition": ResultDisposition.PARTIAL_COVERAGE,
        "tasks": [task("task-1", TaskOutcome.UNAVAILABLE)],
        "finding_ids": [],
        "coverage_receipt_id": "receipt-1",
    }
    result.update(overrides)
    return result


def test_partial_coverage_is_a_valid_non_clean_result() -> None:
    result = ResultContract(**base_result())
    assert result.disposition == ResultDisposition.PARTIAL_COVERAGE
    assert result.integrity_state == IntegrityState.UNSIGNED


def test_no_match_requires_all_tasks_attempted_and_successful() -> None:
    with pytest.raises(ValidationError, match="no_match_in_completed_scope"):
        ResultContract(
            **base_result(
                disposition=ResultDisposition.NO_MATCH_IN_COMPLETED_SCOPE,
                tasks=[
                    task("task-ok", TaskOutcome.NO_MATCH),
                    task("task-unavailable", TaskOutcome.UNAVAILABLE),
                ],
            )
        )


def test_no_match_rejects_unattempted_task() -> None:
    with pytest.raises(ValidationError, match="no_match_in_completed_scope"):
        ResultContract(
            **base_result(
                disposition=ResultDisposition.NO_MATCH_IN_COMPLETED_SCOPE,
                tasks=[task("task-not-run", TaskOutcome.NOT_ATTEMPTED, attempted=False)],
            )
        )


def test_no_match_is_valid_only_with_completed_scope() -> None:
    result = ResultContract(
        **base_result(
            disposition=ResultDisposition.NO_MATCH_IN_COMPLETED_SCOPE,
            tasks=[
                task("task-1", TaskOutcome.SUCCEEDED),
                task("task-2", TaskOutcome.NO_MATCH),
            ],
        )
    )
    assert result.disposition == ResultDisposition.NO_MATCH_IN_COMPLETED_SCOPE


def test_exposed_result_requires_finding_reference() -> None:
    with pytest.raises(ValidationError, match="finding ID"):
        ResultContract(
            **base_result(disposition=ResultDisposition.EXPOSED, finding_ids=[])
        )


def test_exposed_result_accepts_finding_reference() -> None:
    result = ResultContract(
        **base_result(
            disposition=ResultDisposition.EXPOSED,
            finding_ids=["finding-1"],
            tasks=[task("task-1", TaskOutcome.SUCCEEDED)],
        )
    )
    assert result.finding_ids == ["finding-1"]


def test_unsigned_receipt_cannot_claim_signature_metadata() -> None:
    with pytest.raises(ValidationError, match="unsigned receipts"):
        CoverageReceipt(
            receipt_id="receipt-1",
            session_id="session-1",
            asset_id="asset-1",
            issued_at=NOW,
            disposition=ResultDisposition.PARTIAL_COVERAGE,
            integrity_state=IntegrityState.UNSIGNED,
            signing_key_id="key-1",
            signature="signature-placeholder",
        )


def test_verified_receipt_requires_signature_and_key_id() -> None:
    with pytest.raises(ValidationError, match="require signature and signing_key_id"):
        CoverageReceipt(
            receipt_id="receipt-1",
            session_id="session-1",
            asset_id="asset-1",
            issued_at=NOW,
            disposition=ResultDisposition.PARTIAL_COVERAGE,
            integrity_state=IntegrityState.VERIFIED,
        )
