from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from cyclothone.ai.execution_gate import AgentEnvelope, AgentExecutionDenied

def envelope():
    return AgentEnvelope("env-1", uuid4(), uuid4(), "model-a", "provider-a", "kill_process", "kill_process", {"pid": 7}, "device-1", datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1), "kid", "sig", "1", "a" * 64)

def test_envelope_canonical_binds_security_context():
    env = envelope()
    assert env.canonical()["tenant_id"] == str(env.tenant_id)
    assert env.canonical()["model_id"] == "model-a"
    assert env.canonical()["provider_id"] == "provider-a"

@pytest.mark.asyncio
async def test_invalid_signature_fails_closed_before_replay():
    class Replay:
        async def claim(self, **kwargs): raise AssertionError("replay store must not be reached after signature failure")
    gate = __import__("cyclothone.ai.execution_gate", fromlist=["AgentExecutionGate"]).AgentExecutionGate(Replay())
    env = envelope()
    with pytest.raises(AgentExecutionDenied, match="invalid envelope signature"):
        await gate.authorize(envelope=env, tenant_id=env.tenant_id, expected_model_id="model-a", expected_provider_id="provider-a", twin=AsyncMock())

@pytest.mark.asyncio
async def test_destructive_orchestrator_requires_gate():
    from cyclothone.response.orchestrator import ActionPlan, ResponseOrchestrator
    store = AsyncMock()
    store.create = AsyncMock(return_value="1")
    dispatcher = AsyncMock()
    result = await ResponseOrchestrator(dispatcher, store).run_chain(tenant_id=uuid4(), case_id=uuid4(), device_id=uuid4(), plan=[ActionPlan("kill_process", {"pid": 1})], issued_by="test")
    assert result.rejected == ["1"]
    dispatcher.issue.assert_not_called()

@pytest.mark.asyncio
async def test_approval_required_validates_without_consuming_replay(monkeypatch):
    from cyclothone.ai.execution_gate import AgentExecutionGate

    class Replay:
        def __init__(self):
            self.claims = 0
        async def claim(self, **kwargs):
            self.claims += 1
            return True

    replay = Replay()
    gate = AgentExecutionGate(replay)
    env = envelope()

    async def verify(*args, **kwargs):
        return True

    async def policy(*args, **kwargs):
        return {"allowed": False, "requires_approval": True, "reason": "pending_approval"}

    simulation = {"simulation_id": "sim-1", "impact_score": 0.4, "recommendation": "approve"}

    monkeypatch.setattr("cyclothone.ai.execution_gate.verify_digest_signature", verify)
    gate.policy.check = policy
    twin = AsyncMock()
    twin.simulate = AsyncMock(return_value=simulation)

    result = await gate.validate(
        envelope=env,
        tenant_id=env.tenant_id,
        expected_model_id=env.model_id,
        expected_provider_id=env.provider_id,
        twin=twin,
    )

    assert result["authorized"] is True
    assert result["requires_approval"] is True
    assert replay.claims == 0

    await gate.consume(envelope=env, tenant_id=env.tenant_id)
    assert replay.claims == 1


@pytest.mark.asyncio
async def test_denied_policy_is_not_treated_as_approval(monkeypatch):
    from cyclothone.ai.execution_gate import AgentExecutionGate

    class Replay:
        async def claim(self, **kwargs):
            raise AssertionError("replay must not be consumed")

    gate = AgentExecutionGate(Replay())
    env = envelope()

    async def verify(*args, **kwargs):
        return True

    async def policy(*args, **kwargs):
        return {"allowed": False, "requires_approval": False, "reason": "tool_denied_by_policy"}

    monkeypatch.setattr("cyclothone.ai.execution_gate.verify_digest_signature", verify)
    gate.policy.check = policy

    with pytest.raises(AgentExecutionDenied, match="tool_denied_by_policy"):
        await gate.validate(
            envelope=env,
            tenant_id=env.tenant_id,
            expected_model_id=env.model_id,
            expected_provider_id=env.provider_id,
            twin=AsyncMock(),
        )
