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
async def test_unbound_medium_and_high_actions_fail_closed():
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
    assert result.dispatched == []
    assert result.queued == []
    assert len(result.rejected) == 2
    assert dispatcher.calls == []
    assert all("canonical AI run binding is required" in reason for reason in result.reasons.values())


@pytest.mark.asyncio
async def test_unbound_high_action_cannot_enter_approval_queue():
    store = Store()
    dispatcher = Dispatcher()
    result = await ResponseOrchestrator(dispatcher, store).run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan("isolate_host", {})], issued_by="test",
    )
    assert result.queued == []
    assert len(result.rejected) == 1
    assert "canonical AI run binding is required" in next(iter(result.reasons.values()))
    assert dispatcher.calls == []


@pytest.mark.asyncio
async def test_unbound_high_action_cannot_reach_dispatcher():
    store = Store()

    class FailingDispatcher(Dispatcher):
        async def issue(self, **kwargs):
            raise RuntimeError("agent queue unavailable")

    result = await ResponseOrchestrator(FailingDispatcher(), store).run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan("isolate_host", {})], issued_by="test",
    )
    assert result.queued == []
    assert len(result.rejected) == 1
    assert "canonical AI run binding is required" in next(iter(result.reasons.values()))
    assert store.rows[result.rejected[0]]["status"] == "failed"


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


def test_command_canonical_payload_binds_case_action_and_ai_context():
    from cyclothone.response.dispatcher import canonical_command_payload, command_digest

    command_id = uuid4()
    payload = canonical_command_payload(
        command_id=command_id,
        tenant_id=TENANT,
        device_id=DEVICE,
        action="isolate_host",
        args={},
        issued_by="approval:test",
        issued_at=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
        expires_at=__import__("datetime").datetime(2026, 1, 1, 0, 5, tzinfo=__import__("datetime").timezone.utc),
        case_action_id=CASE,
        execution_context={
            "agent_id": str(uuid4()),
            "model_id": "model-a",
            "provider_id": "provider-a",
            "tool_name": "isolate_host",
            "target": "device-1",
            "envelope_id": "env-1",
            "envelope_hash": "a" * 64,
            "args_hash": "b" * 64,
        },
    )

    assert payload["case_action_id"] == str(CASE)
    assert payload["execution_context"]["envelope_id"] == "env-1"
    first = command_digest(payload)
    payload["execution_context"]["envelope_id"] = "env-2"
    assert command_digest(payload) != first
