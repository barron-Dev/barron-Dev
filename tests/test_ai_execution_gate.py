from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from cyclothone.ai.execution_gate import AgentEnvelope, AgentExecutionDenied

def envelope():
    return AgentEnvelope("env-1", uuid4(), uuid4(), "model-a", "provider-a", "kill_process", "kill_process", {"pid": 7}, "device-1", datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1), "kid", "sig")

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