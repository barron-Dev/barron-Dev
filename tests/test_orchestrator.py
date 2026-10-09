from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from cyclothone.response.orchestrator import ACTION_CLASS, ActionClass, ActionPlan, ResponseOrchestrator


class FakeStore:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.rows = {}
        self.n = 0

    async def create(self, **values):
        self.n += 1
        key = str(self.n)
        self.rows[key] = values
        return key

    async def get(self, action_id):
        return self.rows.get(str(action_id)) | {"id": str(action_id)} if str(action_id) in self.rows else None

    async def update(self, action_id, **values):
        self.rows[str(action_id)].update(values)

    async def blast_allowed(self, rule_id, limit, window_minutes=60, tenant_id=None, device_id=None):
        return self.allowed

    async def record_blast(self, **kwargs):
        return None


def test_action_classification():
    assert ACTION_CLASS["scan_now"] == ActionClass.LOW
    assert ACTION_CLASS["kill_process"] == ActionClass.MEDIUM
    assert ACTION_CLASS["isolate_host"] == ActionClass.HIGH
    assert ACTION_CLASS["disable_account"] == ActionClass.CRITICAL


@pytest.mark.asyncio
async def test_high_impact_queued_for_approval():
    from cyclothone.ai.envelope_issuer import EnvelopeIssueRequest
    from cyclothone.ai.execution_gate import AgentEnvelope

    tenant_id = uuid4()
    agent_id = uuid4()
    device_id = uuid4()
    request = EnvelopeIssueRequest(
        tenant_id=tenant_id, agent_id=agent_id, model_id="model-a",
        provider_id="provider-a", tool_name="isolate_host",
        action="isolate_host", args={}, target="device-1",
    )
    envelope = AgentEnvelope(
        "env-approval", tenant_id, agent_id, "model-a", "provider-a",
        "isolate_host", "isolate_host", {}, "device-1",
        datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1),
        "kid", "sig", "1", "b" * 64,
    )
    dispatcher = AsyncMock()
    store = FakeStore()
    issuer = AsyncMock()
    issuer.issue = AsyncMock(return_value=envelope)
    gate = AsyncMock()
    orch = ResponseOrchestrator(
        dispatcher, store, execution_gate=gate, envelope_issuer=issuer,
        execution_authorizer=AsyncMock(),
    )
    result = await orch.run_chain(
        tenant_id=tenant_id, case_id=uuid4(), device_id=device_id,
        plan=[ActionPlan(
            "isolate_host", {}, True, envelope_request=request, run_id=uuid4(),
            model_id="model-a", provider_id="provider-a", target="device-1",
        )],
        issued_by="test",
    )
    assert result.queued == ["1"]
    issuer.issue.assert_awaited_once_with(request)
    gate.validate.assert_awaited_once()
    dispatcher.issue.assert_not_called()


@pytest.mark.asyncio
async def test_dry_run_never_dispatches():
    dispatcher = AsyncMock()
    orch = ResponseOrchestrator(dispatcher, FakeStore())
    result = await orch.run_chain(tenant_id=uuid4(), case_id=uuid4(), device_id=uuid4(), plan=[ActionPlan("kill_process", {"pid": 1})], issued_by="test", dry_run=True)
    assert result.dispatched == ["1"]
    dispatcher.issue.assert_not_called()


@pytest.mark.asyncio
async def test_blast_radius_fails_closed():
    dispatcher = AsyncMock()
    orch = ResponseOrchestrator(dispatcher, FakeStore(allowed=False))
    result = await orch.run_chain(tenant_id=uuid4(), case_id=uuid4(), device_id=uuid4(), plan=[ActionPlan("isolate_host", {}, True)], issued_by="test", blast_rule_id=uuid4(), blast_limit=1)
    assert result.rejected == ["1"]
    assert result.reasons["1"] == "blast radius exceeded"
    dispatcher.issue.assert_not_called()
