from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from cyclothone.response.orchestrator import ActionPlan, ResponseOrchestrator
from cyclothone.response.rollback import RollbackService


TENANT = UUID("11111111-1111-1111-1111-111111111111")
CASE = UUID("22222222-2222-2222-2222-222222222222")
DEVICE = UUID("33333333-3333-3333-3333-333333333333")


class Store:
    def __init__(self, *, blast=True):
        self.rows = {}
        self.blast = blast
        self.blast_records = []

    async def create(self, **values):
        ident = str(uuid4())
        self.rows[ident] = {"id": ident, **values}
        return ident

    async def get(self, action_id):
        return self.rows.get(str(action_id))

    async def update(self, action_id, **values):
        self.rows[str(action_id)].update(values)

    async def blast_allowed(self, rule_id, limit, window_minutes=60, tenant_id=None, device_id=None):
        return self.blast

    async def record_blast(self, **values):
        self.blast_records.append(values)


class Dispatcher:
    def __init__(self):
        self.calls = []

    async def issue(self, **kwargs):
        self.calls.append(kwargs)
        return {"id": str(uuid4()), "status": "pending"}


@pytest.mark.asyncio
async def test_medium_action_dispatches_and_high_action_waits_for_approval():
    store = Store()
    dispatcher = Dispatcher()
    result = await ResponseOrchestrator(dispatcher, store).run_chain(
        tenant_id=TENANT,
        case_id=CASE,
        device_id=DEVICE,
        plan=[
            ActionPlan("block_ip", {"ip": "203.0.113.10"}),
            ActionPlan("isolate_host", {}, requires_approval=False),
        ],
        issued_by="test",
    )
    assert len(result.dispatched) == 1
    assert len(result.queued) == 1
    assert len(dispatcher.calls) == 1
    assert store.rows[result.queued[0]]["status"] == "pending_approval"


@pytest.mark.asyncio
async def test_rejected_approval_never_dispatches():
    store = Store()
    dispatcher = Dispatcher()
    result = await ResponseOrchestrator(dispatcher, store).run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan("isolate_host", {})], issued_by="test",
    )
    action_id = UUID(result.queued[0])
    await ResponseOrchestrator(dispatcher, store).reject(action_id, UUID("44444444-4444-4444-4444-444444444444"), "denied")
    assert store.rows[str(action_id)]["status"] == "rejected"
    assert dispatcher.calls == []


@pytest.mark.asyncio
async def test_approval_dispatch_failure_returns_to_pending():
    store = Store()

    class FailingDispatcher(Dispatcher):
        async def issue(self, **kwargs):
            raise RuntimeError("agent queue unavailable")

    result = await ResponseOrchestrator(FailingDispatcher(), store).run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan("isolate_host", {})], issued_by="test",
    )
    action_id = UUID(result.queued[0])
    with pytest.raises(RuntimeError):
        await ResponseOrchestrator(FailingDispatcher(), store).approve(action_id, UUID("44444444-4444-4444-4444-444444444444"))
    assert store.rows[str(action_id)]["status"] == "pending_approval"


@pytest.mark.asyncio
async def test_blast_denial_creates_rejected_action():
    store = Store(blast=False)
    dispatcher = Dispatcher()
    rule = UUID("55555555-5555-5555-5555-555555555555")
    result = await ResponseOrchestrator(dispatcher, store).run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan("block_ip", {"ip": "203.0.113.11"})],
        issued_by="test", initiated_by_rule=rule, blast_rule_id=rule, blast_limit=1,
    )
    assert len(result.rejected) == 1
    assert dispatcher.calls == []


@pytest.mark.asyncio
async def test_rollback_creates_inverse_command_and_durable_action():
    store = Store()
    dispatcher = Dispatcher()
    original = await store.create(
        tenant_id=str(TENANT), case_id=str(CASE), device_id=str(DEVICE),
        action="isolate_host", args={}, status="success", issued_by="test",
    )
    result = await RollbackService(dispatcher, store).rollback(
        tenant_id=TENANT, case_action_id=UUID(original), actor="test",
    )
    assert result["inverse_action"] == "release_host"
    assert result["status"] == "dispatched"
    assert len(dispatcher.calls) == 1
    source = store.rows[original]
    assert source["rollback_case_action_id"] == result["rollback_case_action_id"]
    rollback = store.rows[result["rollback_case_action_id"]]
    assert rollback["command_id"] == result["rollback_command_id"]
