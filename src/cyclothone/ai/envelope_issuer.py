from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

from cyclothone.ai.execution_gate import AgentEnvelope
from cyclothone.compliance.signing import sign_digest
from cyclothone.storage.supabase_client import supabase


class EnvelopeIssuanceDenied(RuntimeError):
    """Raised when a signed AI execution capability cannot be issued safely."""


class ProviderBinding(Protocol):
    async def resolve(self, *, tenant_id: UUID, agent_id: UUID, model_id: str, provider_id: str) -> dict[str, Any] | None: ...

class MissionAuthority(Protocol):
    async def resolve(self, *, tenant_id: UUID, mission_id: str, version: int, compiled_hash: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class EnvelopeIssueRequest:
    tenant_id: UUID
    agent_id: UUID
    model_id: str
    provider_id: str
    tool_name: str
    action: str
    args: dict[str, Any]
    target: str
    ttl_seconds: int = 300
    version: str = "1"
    mission_id: str | None = None
    mission_version: int | None = None
    mission_hash: str | None = None


def _canonical_hash(envelope: AgentEnvelope) -> str:
    raw = json.dumps(
        envelope.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AIEnvelopeIssuer:
    """Issue short-lived, tenant-bound capabilities from persisted agent authority.

    The issuer never accepts provider credentials and never infers provider authority
    from a model name. A ProviderBinding implementation must explicitly establish
    the tenant/model/provider relationship before signing.
    """

    def __init__(self, provider_binding: ProviderBinding, mission_authority: MissionAuthority | None = None) -> None:
        self.provider_binding = provider_binding
        self.mission_authority = mission_authority

    async def issue(self, request: EnvelopeIssueRequest) -> AgentEnvelope:
        if request.version != "1":
            raise EnvelopeIssuanceDenied("unsupported envelope version")
        if not 1 <= request.ttl_seconds <= 900:
            raise EnvelopeIssuanceDenied("invalid envelope ttl")
        if not request.model_id or len(request.model_id) > 128:
            raise EnvelopeIssuanceDenied("invalid model id")
        if not request.provider_id or len(request.provider_id) > 128:
            raise EnvelopeIssuanceDenied("invalid provider id")
        if request.tool_name != request.action:
            raise EnvelopeIssuanceDenied("tool/action binding mismatch")
        if not request.target or len(request.target) > 512:
            raise EnvelopeIssuanceDenied("invalid target")
        if not request.mission_id or request.mission_version is None or not request.mission_hash:
            raise EnvelopeIssuanceDenied("mission binding is required")
        if self.mission_authority is None:
            raise EnvelopeIssuanceDenied("mission authority is required")
        if len(request.mission_hash) != 64 or any(c not in "0123456789abcdef" for c in request.mission_hash):
            raise EnvelopeIssuanceDenied("invalid mission hash")
        mission = await self.mission_authority.resolve(tenant_id=request.tenant_id, mission_id=request.mission_id, version=request.mission_version, compiled_hash=request.mission_hash)
        if not mission or mission.get("active") is not True:
            raise EnvelopeIssuanceDenied("mission is not active")

        agent = await supabase.select_one(
            "ai_agents",
            "id,tenant_id,model,declared_tools,status",
            id=str(request.agent_id),
            tenant_id=str(request.tenant_id),
        )
        if not agent or str(agent.get("status")) != "active":
            raise EnvelopeIssuanceDenied("agent is not active")
        if str(agent.get("model") or "") != request.model_id:
            raise EnvelopeIssuanceDenied("agent/model binding mismatch")

        declared = {str(x) for x in (agent.get("declared_tools") or [])}
        if request.tool_name not in declared:
            raise EnvelopeIssuanceDenied("tool is not declared by agent")

        binding = await self.provider_binding.resolve(
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            model_id=request.model_id,
            provider_id=request.provider_id,
        )
        if not binding or binding.get("active") is not True:
            raise EnvelopeIssuanceDenied("provider binding is not active")

        issued_at = datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=request.ttl_seconds)
        envelope = AgentEnvelope(
            envelope_id="env_" + uuid4().hex,
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            model_id=request.model_id,
            provider_id=request.provider_id,
            tool_name=request.tool_name,
            action=request.action,
            args=request.args,
            target=request.target,
            issued_at=issued_at,
            expires_at=expires_at,
            signer_kid="",
            signature_b64="",
            version=request.version,
            binding_hash=str(binding.get("binding_hash") or ""),
            mission_id=request.mission_id,
            mission_version=request.mission_version,
            mission_hash=request.mission_hash,
        )
        if (
            len(envelope.binding_hash) != 64
            or any(c not in "0123456789abcdef" for c in envelope.binding_hash)
        ):
            raise EnvelopeIssuanceDenied("provider binding has no valid binding hash")

        digest = _canonical_hash(envelope)
        signature = await sign_digest(digest)
        return AgentEnvelope(
            envelope_id=envelope.envelope_id,
            tenant_id=envelope.tenant_id,
            agent_id=envelope.agent_id,
            model_id=envelope.model_id,
            provider_id=envelope.provider_id,
            tool_name=envelope.tool_name,
            action=envelope.action,
            args=envelope.args,
            target=envelope.target,
            issued_at=envelope.issued_at,
            expires_at=envelope.expires_at,
            signer_kid=signature.kid,
            signature_b64=signature.signature_b64,
            version=envelope.version,
            binding_hash=envelope.binding_hash,
            mission_id=envelope.mission_id,
            mission_version=envelope.mission_version,
            mission_hash=envelope.mission_hash,
        )
