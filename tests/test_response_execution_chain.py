from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from cyclothone.ai.envelope_issuer import EnvelopeIssueRequest
from cyclothone.ai.execution_gate import AgentEnvelope
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


def trusted_plan(action, args, *, requires_approval=False):
    agent_id = uuid4()
    mission_id = "mission-test"
    mission_hash = "a" * 64
    request = EnvelopeIssueRequest(
        tenant_id=TENANT, agent_id=agent_id, model_id="model-test",
        provider_id="provider-test", tool_name=action, action=action,
        args=args, target=str(DEVICE), mission_id=mission_id,
        mission_version=1, mission_hash=mission_hash,
    )
    return ActionPlan(
        action, args, requires_approval=requires_approval,
        envelope_request=request, model_id=request.model_id,
        provider_id=request.provider_id, target=request.target,
        mission_id=mission_id, mission_version=1, mission_hash=mission_hash,
        run_id=uuid4(),
    )


def trusted_orchestrator(dispatcher, store, monkeypatch):
    import cyclothone.response.orchestrator as orchestrator_module

    monkeypatch.setattr("cyclothone.twin.service.DigitalTwinService", lambda tenant_id: object())
    monkeypatch.setattr(orchestrator_module, "create_response_execution_approval", AsyncMock(return_value={}))
    monkeypatch.setattr(orchestrator_module, "complete_response_execution", AsyncMock(return_value={}))
    issuer = AsyncMock()

    async def issue(request):
        now = datetime.now(UTC)
        return AgentEnvelope(
            envelope_id="env-" + uuid4().hex, tenant_id=request.tenant_id,
            agent_id=request.agent_id, model_id=request.model_id,
            provider_id=request.provider_id, tool_name=request.tool_name,
            action=request.action, args=request.args, target=request.target,
            issued_at=now, expires_at=now + timedelta(minutes=5),
            signer_kid="test-kid", signature_b64="test-signature",
            version="1", binding_hash="b" * 64,
            mission_id=request.mission_id, mission_version=request.mission_version,
            mission_hash=request.mission_hash,
        )

    issuer.issue.side_effect = issue
    gate = AsyncMock()
    gate.validate.return_value = {
        "authorized": True, "requires_approval": False,
        "simulation_id": "sim-test", "impact_score": 0.1,
        "recommendation": "approve",
    }
    return ResponseOrchestrator(
        dispatcher, store, execution_gate=gate, envelope_issuer=issuer,
        execution_authorizer=AsyncMock(return_value={"allowed": True, "committed": True}),
    )


@pytest.mark.asyncio
async def test_medium_action_dispatches_and_high_action_waits_for_approval(monkeypatch):
    store = Store()
    dispatcher = Dispatcher()
    result = await trusted_orchestrator(dispatcher, store, monkeypatch).run_chain(
        tenant_id=TENANT,
        case_id=CASE,
        device_id=DEVICE,
        plan=[
            trusted_plan("block_ip", {"ip": "203.0.113.10"}),
            trusted_plan("isolate_host", {}, requires_approval=False),
        ],
        issued_by="test",
    )
    assert len(result.dispatched) == 1
    assert len(result.queued) == 1
    assert len(dispatcher.calls) == 1
    assert store.rows[result.queued[0]]["status"] == "pending_approval"


@pytest.mark.asyncio
async def test_rejected_approval_never_dispatches(monkeypatch):
    store = Store()
    dispatcher = Dispatcher()
    orchestrator = trusted_orchestrator(dispatcher, store, monkeypatch)
    result = await orchestrator.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[trusted_plan("isolate_host", {})], issued_by="test",
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

    orchestrator = trusted_orchestrator(FailingDispatcher(), store, monkeypatch)
    result = await orchestrator.run_chain(
        tenant_id=TENANT, case_id=CASE, device_id=DEVICE,
        plan=[trusted_plan("isolate_host", {})], issued_by="test",
    )
    action_id = UUID(result.queued[0])
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
