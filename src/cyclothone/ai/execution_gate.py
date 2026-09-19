from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from cyclothone.ai.tool_policy import ToolPolicyEngine
from cyclothone.compliance.signing import verify_digest_signature
from cyclothone.twin.service import DigitalTwinService

class ReplayStore(Protocol):
    async def claim(self, *, tenant_id: UUID, envelope_id: str, expires_at: datetime) -> bool: ...

@dataclass(frozen=True, slots=True)
class AgentEnvelope:
    envelope_id: str
    tenant_id: UUID
    agent_id: UUID
    model_id: str
    provider_id: str
    tool_name: str
    action: str
    args: dict[str, Any]
    target: str
    issued_at: datetime
    expires_at: datetime
    signer_kid: str
    signature_b64: str

    def canonical(self) -> dict[str, Any]:
        return {"envelope_id": self.envelope_id, "tenant_id": str(self.tenant_id), "agent_id": str(self.agent_id), "model_id": self.model_id, "provider_id": self.provider_id, "tool_name": self.tool_name, "action": self.action, "args": self.args, "target": self.target, "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat()}

class AgentExecutionDenied(RuntimeError):
    pass

class AgentExecutionGate:
    """Fail-closed boundary between AI intent and destructive response dispatch."""
    def __init__(self, replay_store: ReplayStore, policy: ToolPolicyEngine | None = None) -> None:
        self.replay_store = replay_store
        self.policy = policy or ToolPolicyEngine()

    async def authorize(self, *, envelope: AgentEnvelope, tenant_id: UUID, expected_model_id: str, expected_provider_id: str, twin: DigitalTwinService) -> dict[str, Any]:
        now = datetime.now(UTC)
        if envelope.tenant_id != tenant_id: raise AgentExecutionDenied("envelope tenant mismatch")
        if envelope.expires_at <= now or envelope.issued_at > now: raise AgentExecutionDenied("envelope expired or issued in the future")
        if envelope.model_id != expected_model_id: raise AgentExecutionDenied("model binding mismatch")
        if envelope.provider_id != expected_provider_id: raise AgentExecutionDenied("provider binding mismatch")
        if not envelope.envelope_id or len(envelope.envelope_id) > 128: raise AgentExecutionDenied("invalid envelope id")
        if not envelope.tool_name or not envelope.action or envelope.tool_name != envelope.action: raise AgentExecutionDenied("tool/action binding mismatch")
        digest = hashlib.sha256(json.dumps(envelope.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        if not await verify_digest_signature(digest, envelope.signature_b64, envelope.signer_kid): raise AgentExecutionDenied("invalid envelope signature")
        if not await self.replay_store.claim(tenant_id=tenant_id, envelope_id=envelope.envelope_id, expires_at=envelope.expires_at): raise AgentExecutionDenied("envelope replay detected")
        policy = await self.policy.check(tenant_id, envelope.agent_id, envelope.tool_name, envelope.args)
        if not policy.get("allowed") or policy.get("requires_approval"): raise AgentExecutionDenied(str(policy.get("reason") or "tool policy denied"))
        simulation = await twin.simulate(envelope.target, envelope.action, envelope.args)
        return {"authorized": True, "envelope_id": envelope.envelope_id, "simulation_id": simulation["simulation_id"], "impact_score": simulation["impact_score"], "recommendation": simulation["recommendation"]}