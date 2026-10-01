from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from cyclothone.ai.execution_gate import AgentEnvelope, AgentExecutionDenied

def envelope():
    return AgentEnvelope("env-1", uuid4(), uuid4(), "model-a", "provider-a", "kill_process", "kill_process", {"pid": 7}, "device-1", datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1), "kid", "sig", "1", "a" * 64, "mission-a", 1, "d" * 64)

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
        expected_mission_id=env.mission_id,
        expected_mission_version=env.mission_version,
        expected_mission_hash=env.mission_hash,
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
            expected_mission_id=env.mission_id,
            expected_mission_version=env.mission_version,
            expected_mission_hash=env.mission_hash,
            twin=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_envelope_issuer_requires_authoritative_agent_and_provider_binding(monkeypatch):
    from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer, EnvelopeIssueRequest
    from cyclothone.compliance.signing import ComplianceSignature

    tenant = uuid4()
    agent_id = uuid4()

    async def owned(*args, **kwargs):
        return {
            "id": str(agent_id), "tenant_id": str(tenant), "model": "model-a",
            "declared_tools": ["isolate_host"], "status": "active",
        }

    class Provider:
        async def resolve(self, **kwargs):
            assert kwargs["tenant_id"] == tenant
            assert kwargs["model_id"] == "model-a"
            assert kwargs["provider_id"] == "provider-a"
            return {"active": True, "binding_hash": "c" * 64}

    monkeypatch.setattr("cyclothone.ai.envelope_issuer.supabase.select_one", owned)
    monkeypatch.setattr(
        "cyclothone.ai.envelope_issuer.sign_digest",
        AsyncMock(return_value=ComplianceSignature("signed", "kid-1")),
    )

    env = await AIEnvelopeIssuer(Provider(), AsyncMock(resolve=AsyncMock(return_value={"active": True}))).issue(
        EnvelopeIssueRequest(
            tenant_id=tenant, agent_id=agent_id, model_id="model-a",
            provider_id="provider-a", tool_name="isolate_host",
            action="isolate_host", args={}, target="device-1", mission_id="mission-a", mission_version=1, mission_hash="d" * 64,
        )
    )
    assert env.tenant_id == tenant
    assert env.binding_hash == "c" * 64
    assert env.signer_kid == "kid-1"
    assert env.signature_b64 == "signed"


@pytest.mark.asyncio
async def test_envelope_issuer_rejects_undeclared_tool(monkeypatch):
    from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer, EnvelopeIssueRequest

    tenant = uuid4()
    agent_id = uuid4()

    async def owned(*args, **kwargs):
        return {"id": str(agent_id), "tenant_id": str(tenant), "model": "model-a",
                "declared_tools": [], "status": "active"}

    monkeypatch.setattr("cyclothone.ai.envelope_issuer.supabase.select_one", owned)

    with pytest.raises(Exception, match="tool is not declared by agent"):
        await AIEnvelopeIssuer(AsyncMock(), AsyncMock(resolve=AsyncMock(return_value={"active": True}))).issue(
            EnvelopeIssueRequest(
                tenant_id=tenant, agent_id=agent_id, model_id="model-a",
                provider_id="provider-a", tool_name="isolate_host",
                action="isolate_host", args={}, target="device-1", mission_id="mission-a", mission_version=1, mission_hash="d" * 64,
            )
        )


@pytest.mark.asyncio
async def test_envelope_issuer_requires_persisted_provider_authority(monkeypatch):
    from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer, EnvelopeIssueRequest, EnvelopeIssuanceDenied
    from cyclothone.compliance.signing import ComplianceSignature

    tenant_id = uuid4()
    agent_id = uuid4()

    async def select_one(table, columns, **filters):
        if table == "ai_agents":
            return {
                "id": str(agent_id), "tenant_id": str(tenant_id), "model": "model-a",
                "declared_tools": ["kill_process"], "status": "active",
            }
        raise AssertionError(f"unexpected table: {table}")

    monkeypatch.setattr("cyclothone.ai.envelope_issuer.supabase.select_one", select_one)

    class Binding:
        async def resolve(self, **kwargs):
            return None

    issuer = AIEnvelopeIssuer(Binding(), AsyncMock(resolve=AsyncMock(return_value={"active": True})))
    with pytest.raises(EnvelopeIssuanceDenied, match="provider binding"):
        await issuer.issue(EnvelopeIssueRequest(
            tenant_id=tenant_id, agent_id=agent_id, model_id="model-a",
            provider_id="provider-a", tool_name="kill_process", action="kill_process",
            args={"pid": 7}, target="device-1", mission_id="mission-a", mission_version=1, mission_hash="d" * 64,
        ))


@pytest.mark.asyncio
async def test_envelope_issuer_signs_only_bound_agent(monkeypatch):
    from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer, EnvelopeIssueRequest
    from cyclothone.compliance.signing import ComplianceSignature

    tenant_id = uuid4()
    agent_id = uuid4()

    async def select_one(table, columns, **filters):
        if table == "ai_agents":
            return {
                "id": str(agent_id), "tenant_id": str(tenant_id), "model": "model-a",
                "declared_tools": ["kill_process"], "status": "active",
            }
        raise AssertionError(f"unexpected table: {table}")

    monkeypatch.setattr("cyclothone.ai.envelope_issuer.supabase.select_one", select_one)
    async def sign(digest, *, purpose):
        assert len(digest) == 64
        assert purpose == "AI_ENVELOPE"
        return ComplianceSignature(signature_b64="sig", kid="kid-1")
    monkeypatch.setattr("cyclothone.ai.envelope_issuer.sign_digest", sign)

    class Binding:
        async def resolve(self, **kwargs):
            return {"active": True, "binding_hash": "a" * 64}

    envelope = await AIEnvelopeIssuer(Binding(), AsyncMock(resolve=AsyncMock(return_value={"active": True}))).issue(EnvelopeIssueRequest(
        tenant_id=tenant_id, agent_id=agent_id, model_id="model-a",
        provider_id="provider-a", tool_name="kill_process", action="kill_process",
        args={"pid": 7}, target="device-1", mission_id="mission-a", mission_version=1, mission_hash="d" * 64,
    ))

    assert envelope.tenant_id == tenant_id
    assert envelope.agent_id == agent_id
    assert envelope.signer_kid == "kid-1"
    assert envelope.signature_b64 == "sig"
    assert envelope.binding_hash == "a" * 64


@pytest.mark.asyncio
async def test_destructive_orchestrator_rejects_client_supplied_envelope_without_issuance_request():
    from cyclothone.response.orchestrator import ActionPlan, ResponseOrchestrator

    tenant = uuid4()
    store = AsyncMock()
    store.create = AsyncMock(return_value="1")
    dispatcher = AsyncMock()
    gate = AsyncMock()
    result = await ResponseOrchestrator(dispatcher, store, execution_gate=gate, envelope_issuer=AsyncMock()).run_chain(
        tenant_id=tenant, case_id=uuid4(), device_id=uuid4(),
        plan=[ActionPlan("kill_process", {"pid": 7}, agent_envelope=envelope(), model_id="model-a", provider_id="provider-a", target="device-1", run_id=uuid4())],
        issued_by="test",
    )
    assert result.rejected == ["1"]
    assert "issuance request" in result.reasons["1"]
    dispatcher.issue.assert_not_called()


@pytest.mark.asyncio
async def test_destructive_orchestrator_mints_and_consumes_authoritative_envelope():
    from cyclothone.response.orchestrator import ActionPlan, ResponseOrchestrator
    from cyclothone.ai.envelope_issuer import EnvelopeIssueRequest

    tenant = uuid4()
    agent = uuid4()
    env = AgentEnvelope(
        "env-issued", tenant, agent, "model-a", "provider-a", "kill_process", "kill_process",
        {"pid": 7}, "device-1", datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1),
        "kid", "sig", "1", "b" * 64, "mission-a", 1, "d" * 64,
    )
    request = EnvelopeIssueRequest(
        tenant_id=tenant, agent_id=agent, model_id="model-a", provider_id="provider-a",
        tool_name="kill_process", action="kill_process", args={"pid": 7}, target="device-1", mission_id="mission-a", mission_version=1, mission_hash="d" * 64,
    )
    issuer = AsyncMock()
    issuer.issue = AsyncMock(return_value=env)
    gate = AsyncMock()
    store = AsyncMock()
    action_id = str(uuid4())
    store.create = AsyncMock(return_value=action_id)
    store.update = AsyncMock()
    dispatcher = AsyncMock()
    dispatcher.issue = AsyncMock(return_value={"id": "cmd-1"})

    execution_authorizer = AsyncMock()
    execution_authorizer.return_value = object()
    result = await ResponseOrchestrator(
        dispatcher, store, execution_gate=gate, envelope_issuer=issuer,
        execution_authorizer=execution_authorizer,
    ).run_chain(
        tenant_id=tenant, case_id=uuid4(), device_id=uuid4(),
        plan=[ActionPlan("kill_process", {"pid": 7}, envelope_request=request, run_id=uuid4())],
        issued_by="test",
    )

    assert result.dispatched == [action_id]
    issuer.issue.assert_awaited_once_with(request)
    gate.validate.assert_awaited_once()
    gate.consume.assert_awaited_once()
    dispatcher.issue.assert_awaited_once()


@pytest.mark.asyncio
async def test_execution_gate_rejects_stale_mission_binding(monkeypatch):
    from cyclothone.ai.execution_gate import AgentExecutionGate

    gate = AgentExecutionGate(AsyncMock())
    env = AgentEnvelope(
        "env-mission", uuid4(), uuid4(), "model-a", "provider-a", "kill_process", "kill_process",
        {"pid": 7}, "device-1", datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1),
        "kid", "sig", "1", "a" * 64, "mission-a", 2, "d" * 64,
    )
    monkeypatch.setattr("cyclothone.ai.execution_gate.verify_digest_signature", AsyncMock(return_value=True))
    gate.policy.check = AsyncMock(return_value={"allowed": True, "requires_approval": False})
    with pytest.raises(AgentExecutionDenied, match="mission binding mismatch"):
        await gate.validate(
            envelope=env, tenant_id=env.tenant_id, expected_model_id="model-a",
            expected_provider_id="provider-a", expected_mission_id="mission-a",
            expected_mission_version=1, expected_mission_hash="d" * 64, twin=AsyncMock(),
        )


def test_mission_binding_changes_envelope_canonical_digest():
    from cyclothone.ai.execution_gate import AgentExecutionGate
    env = envelope()
    a = AgentExecutionGate._envelope_hash(env)
    changed = AgentEnvelope(
        env.envelope_id, env.tenant_id, env.agent_id, env.model_id, env.provider_id,
        env.tool_name, env.action, env.args, env.target, env.issued_at, env.expires_at,
        env.signer_kid, env.signature_b64, env.version, env.binding_hash,
        "mission-b", 2, "e" * 64,
    )
    assert a != AgentExecutionGate._envelope_hash(changed)
