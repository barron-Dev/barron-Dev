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
