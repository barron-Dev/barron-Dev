from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from cyclothone.response.rollback import RollbackConflict, RollbackError, RollbackService


@pytest.mark.asyncio
async def test_refuses_irreversible_action() -> None:
    dispatcher = AsyncMock()
    store = AsyncMock()
    tenant_id = uuid4()
    action_id = uuid4()
    store.get.return_value = {
        "id": str(action_id),
        "tenant_id": str(tenant_id),
        "device_id": str(uuid4()),
        "action": "kill_process",
        "args": {"pid": 1},
        "status": "success",
        "rolled_back_at": None,
    }

    service = RollbackService(dispatcher, store)
    with pytest.raises(RollbackError, match="no defined inverse"):
        await service.rollback(tenant_id=tenant_id, case_action_id=action_id, actor="test")
    dispatcher.issue.assert_not_awaited()


@pytest.mark.asyncio
async def test_quarantine_file_rollback_persists_while_inverse_executes() -> None:
    dispatcher = AsyncMock()
    dispatcher.issue.return_value = {"id": str(uuid4()), "status": "executing"}
    store = AsyncMock()
    tenant_id = uuid4()
    action_id = uuid4()
    store.get.return_value = {
        "id": str(action_id),
        "tenant_id": str(tenant_id),
        "device_id": str(uuid4()),
        "action": "quarantine_file",
        "args": {"path": "/tmp/bad.exe"},
        "status": "success",
        "rolled_back_at": None,
    }

    service = RollbackService(dispatcher, store)
    result = await service.rollback(tenant_id=tenant_id, case_action_id=action_id, actor="test")
    assert result["status"] == "dispatched"
    kwargs = dispatcher.issue.await_args.kwargs
    assert kwargs["action"] == "restore_file"
    assert kwargs["args"] == {"original": "/tmp/bad.exe"}
    assert store.update.await_count == 2
    assert store.update.await_args.kwargs["rollback_command_id"] == result["rollback_command_id"]


@pytest.mark.asyncio
async def test_quarantine_file_rollback_creates_inverse_action() -> None:
    dispatcher = AsyncMock()
    command_id = str(uuid4())
    dispatcher.issue.return_value = {"id": command_id, "status": "success"}
    store = AsyncMock()
    tenant_id = uuid4()
    action_id = uuid4()
    device_id = uuid4()
    store.get.return_value = {
        "id": str(action_id),
        "tenant_id": str(tenant_id),
        "device_id": str(device_id),
        "action": "quarantine_file",
        "args": {"path": "/tmp/bad.exe"},
        "status": "success",
        "rolled_back_at": None,
    }

    result = await RollbackService(dispatcher, store).rollback(
        tenant_id=tenant_id, case_action_id=action_id, actor="test"
    )

    assert result["inverse_action"] == "restore_file"
    assert result["inverse_args"] == {"original": "/tmp/bad.exe"}
    assert result["rollback_command_id"] == command_id
    assert result["status"] == "dispatched"
    assert store.update.await_count == 2
    source_update = store.update.await_args_list[-1].kwargs
    assert source_update["rollback_command_id"] == command_id
    assert source_update["rollback_case_action_id"]


@pytest.mark.asyncio
async def test_tenant_mismatch_is_not_accessible() -> None:
    dispatcher = AsyncMock()
    store = AsyncMock()
    action_id = uuid4()
    store.get.return_value = {
        "id": str(action_id),
        "tenant_id": str(uuid4()),
        "status": "success",
    }

    with pytest.raises(RollbackConflict, match="not found"):
        await RollbackService(dispatcher, store).rollback(
            tenant_id=uuid4(), case_action_id=action_id, actor="test"
        )
    dispatcher.issue.assert_not_awaited()
