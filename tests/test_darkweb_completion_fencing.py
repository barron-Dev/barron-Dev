from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cyclothone.darkweb.request_worker import DarkWebRequestWorker


@pytest.mark.asyncio
async def test_completion_passes_claim_attempt_as_fencing_token(monkeypatch):
    rpc = AsyncMock(return_value=True)
    monkeypatch.setattr("cyclothone.darkweb.request_worker.supabase.rpc", rpc)
    worker = DarkWebRequestWorker()

    await worker._complete(
        {"id": "00000000-0000-0000-0000-000000000001", "attempts": 2},
        "succeeded",
        "resolved",
        {"coverage": "partial"},
        None,
    )

    rpc.assert_awaited_once_with(
        "complete_service_request",
        {
            "p_id": "00000000-0000-0000-0000-000000000001",
            "p_attempt": 2,
            "p_state": "succeeded",
            "p_status": "resolved",
            "p_result": {"coverage": "partial"},
            "p_failure_code": None,
        },
    )



@pytest.mark.asyncio
async def test_completion_rejected_by_fence_is_not_treated_as_success(monkeypatch):
    rpc = AsyncMock(return_value=False)
    monkeypatch.setattr("cyclothone.darkweb.request_worker.supabase.rpc", rpc)
    worker = DarkWebRequestWorker()

    with pytest.raises(RuntimeError, match="completion_fence_rejected"):
        await worker._complete(
            {"id": "00000000-0000-0000-0000-000000000001", "attempts": 2},
            "succeeded",
            "resolved",
            {"coverage": "partial"},
            None,
        )

    rpc.assert_awaited_once()


def test_finding_persistence_requires_database_confirmation_of_finding_and_alert():
    from cyclothone.darkweb.request_worker import _require_recorded_finding

    recorded = _require_recorded_finding([{"finding_id": 123, "alert_id": "alert-1", "detection_id": "detection-1"}])
    assert recorded["finding_id"] == 123


@pytest.mark.parametrize("response", [None, [], [{}], [{"finding_id": 123}], [{"alert_id": "alert-1"}]])
def test_finding_persistence_rejects_unconfirmed_rpc_results(response):
    from cyclothone.darkweb.request_worker import _require_recorded_finding

    with pytest.raises(RuntimeError, match="finding_persistence_unconfirmed"):
        _require_recorded_finding(response)
