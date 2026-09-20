from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cyclothone.trust.scheduler import TrustReevaluationScheduler


@pytest.mark.asyncio
async def test_worker_processes_claimed_job_and_settles_success(monkeypatch):
    scheduler = TrustReevaluationScheduler()
    rpc = AsyncMock(
        side_effect=[
            {"state": "VERIFIED", "state_hash": "a" * 64},
            None,
        ]
    )
    monkeypatch.setattr("cyclothone.trust.scheduler.supabase.rpc", rpc)
    heartbeat = AsyncMock()
    monkeypatch.setattr(scheduler, "_heartbeat", heartbeat)

    await scheduler._process(
        {"id": "queue-1", "subject_id": "subject-1"}
    )

    assert rpc.await_args_list[0].args[0] == "trust_continuous_verify_subject"
    assert rpc.await_args_list[0].args[1] == {"p_subject_id": "subject-1"}
    assert rpc.await_args_list[1].args[0] == "trust_complete_re_evaluation"
    assert rpc.await_args_list[1].args[1]["p_queue_id"] == "queue-1"
    assert rpc.await_args_list[1].args[1]["p_success"] is True
    heartbeat.assert_awaited_once_with("RUNNING")


@pytest.mark.asyncio
async def test_worker_settles_failed_job_without_leaking_exception(monkeypatch):
    scheduler = TrustReevaluationScheduler()
    rpc = AsyncMock(
        side_effect=[
            RuntimeError("verification failed"),
            None,
        ]
    )
    monkeypatch.setattr("cyclothone.trust.scheduler.supabase.rpc", rpc)
    heartbeat = AsyncMock()

    monkeypatch.setattr(scheduler, "_heartbeat", heartbeat)

    await scheduler._process(
        {"id": "queue-2", "subject_id": "subject-2"}
    )

    assert rpc.await_args_list[0].args[0] == "trust_continuous_verify_subject"
    assert rpc.await_args_list[1].args[0] == "trust_complete_re_evaluation"
    failure_payload = rpc.await_args_list[1].args[1]
    assert failure_payload["p_queue_id"] == "queue-2"
    assert failure_payload["p_success"] is False
    assert failure_payload["p_result"] == {"subject_id": "subject-2"}
    assert failure_payload["p_error"] == "verification failed"
    heartbeat.assert_awaited_once_with("ERROR", error_code="job_failed")


@pytest.mark.asyncio
async def test_worker_rejects_malformed_claim(monkeypatch):
    scheduler = TrustReevaluationScheduler()
    heartbeat = AsyncMock()
    monkeypatch.setattr(scheduler, "_heartbeat", heartbeat)

    await scheduler._process({"id": None, "subject_id": "subject-1"})

    heartbeat.assert_awaited_once_with("ERROR", error_code="invalid_job")


@pytest.mark.asyncio
async def test_worker_heartbeat_is_service_boundary(monkeypatch):
    scheduler = TrustReevaluationScheduler()
    rpc = AsyncMock()
    monkeypatch.setattr("cyclothone.trust.scheduler.supabase.rpc", rpc)

    await scheduler._heartbeat("RUNNING")

    rpc.assert_awaited_once()
    name, payload = rpc.await_args.args
    assert name == "trust_worker_heartbeat"
    assert payload["p_worker_name"] == "trust-reevaluation"
    assert payload["p_status"] == "RUNNING"
    assert payload["p_success"] is True
    assert payload["p_metadata"]["claim_limit"] == scheduler.CLAIM_LIMIT
