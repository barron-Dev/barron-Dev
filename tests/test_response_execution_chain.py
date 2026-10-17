from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from cyclothone.response.orchestrator import ActionPlan, ResponseOrchestrator
from cyclothone.response.rollback import RollbackService
from cyclothone.ai.envelope_issuer import EnvelopeIssueRequest
from cyclothone.ai.execution_gate import AgentEnvelope


TENANT = UUID("11111111-1111-1111-1111-111111111111")
CASE = UUID("22222222-2222-2222-2222-222222222222")
DEVICE = UUID("33333333-3333-3333-3333-333333333333")


def secure_plan(action, args, *, requires_approval=False):
    agent_id = uuid4()
    run_id = uuid4()
    target = "device-1"
    mission_id = "mission-a"
    mission_hash = "d" * 64
    request = EnvelopeIssueRequest(
        tenant_id=TENANT, agent_id=agent_id, model_id="model-a",
        provider_id="provider-a", tool_name=action, action=action,
        args=args, target=target, mission_id=mission_id,
        mission_version=1, mission_hash=mission_hash,
    )
    envelope = AgentEnvelope(
        "env-test", TENANT, agent_id, "model-a", "provider-a", action, action,
        args, target, datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1),
        "kid", "sig", "1", "a" * 64, mission_id, 1, mission_hash,
    )
    return ActionPlan(
        action, args, requires_approval=requires_approval,
        envelope_request=request, run_id=run_id, model_id="model-a",
        provider_id="provider-a", target=target, mission_id=mission_id,
        mission_version=1, mission_hash=mission_hash,
    ), envelope


def secure_orchestrator(dispatcher, store, action, args, *, requires_approval=False):
    plan, envelope = secure_plan(action, args, requires_approval=requires_approval)
    issuer = AsyncMock()
    issuer.issue = AsyncMock(return_value=envelope)
    gate = AsyncMock()
    gate.validate = AsyncMock(return_value={"authorized": True, "requires_approval": requires_approval})
    gate.consume = AsyncMock()
    authorizer = AsyncMock()
    orchestrator = ResponseOrchestrator(
        dispatcher, store, execution_gate=gate, envelope_issuer=issuer,
        execution_authorizer=authorizer,
    )
    return orchestrator, plan


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
    medium, _ = secure_orchestrator(dispatcher, store, "block_ip", {"ip": "203.0.113.10"})
    high, high_plan = secure_orchestrator(dispatcher, store, "isolate_host", {}, requires_approval=False)
    result = await medium.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[secure_plan("block_ip", {"ip": "203.0.113.10"})[0]],
        issued_by="test",
    )
    high_result = await high.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[high_plan], issued_by="test",
    )
    result.dispatched.extend(high_result.dispatched)
    result.queued.extend(high_result.queued)
    result.rejected.extend(high_result.rejected)
    result.reasons.update(high_result.reasons)
    assert len(result.dispatched) == 1
    assert len(result.queued) == 1
    assert len(dispatcher.calls) == 1
    assert store.rows[result.queued[0]]["status"] == "pending_approval"


@pytest.mark.asyncio
async def test_rejected_approval_never_dispatches():
    store = Store()
    dispatcher = Dispatcher()
    orchestrator, plan = secure_orchestrator(dispatcher, store, "isolate_host", {})
    result = await orchestrator.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[ActionPlan(plan.action, plan.args, requires_approval=True, envelope_request=plan.envelope_request, run_id=plan.run_id, model_id=plan.model_id, provider_id=plan.provider_id, target=plan.target, mission_id=plan.mission_id, mission_version=plan.mission_version, mission_hash=plan.mission_hash)], issued_by="test",
    )
    action_id = UUID(result.queued[0])
    await orchestrator.reject(action_id, UUID("44444444-4444-4444-4444-444444444444"), "denied")
    assert store.rows[str(action_id)]["status"] == "rejected"
    assert dispatcher.calls == []


@pytest.mark.asyncio
async def test_approval_dispatch_failure_returns_to_pending(monkeypatch):
    store = Store()

    class FailingDispatcher(Dispatcher):
        async def issue(self, **kwargs):
            raise RuntimeError("agent queue unavailable")

    orchestrator, plan = secure_orchestrator(FailingDispatcher(), store, "isolate_host", {})
    plan = ActionPlan(plan.action, plan.args, requires_approval=True, envelope_request=plan.envelope_request, run_id=plan.run_id, model_id=plan.model_id, provider_id=plan.provider_id, target=plan.target, mission_id=plan.mission_id, mission_version=plan.mission_version, mission_hash=plan.mission_hash)
    result = await orchestrator.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE, plan=[plan], issued_by="test",
    )
    action_id = UUID(result.queued[0])
    async def no_op(*args, **kwargs):
        return None
    orchestrator._fail_committed_execution = no_op
    monkeypatch.setattr("cyclothone.response.orchestrator.create_response_execution_approval", no_op)
    with pytest.raises(RuntimeError):
        await orchestrator.approve(action_id, UUID("44444444-4444-4444-4444-444444444444"))
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
