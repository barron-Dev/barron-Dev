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
from cyclothone.storage.supabase_client import supabase

class ReplayStore(Protocol):
    async def claim(self, *, tenant_id: UUID, envelope_id: str, expires_at: datetime, envelope_hash: str) -> bool: ...

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
    version: str = "1"
    binding_hash: str = ""
    mission_id: str | None = None
    mission_version: int | None = None
    mission_hash: str | None = None

    def canonical(self) -> dict[str, Any]:
        return {"envelope_id": self.envelope_id, "tenant_id": str(self.tenant_id), "agent_id": str(self.agent_id), "model_id": self.model_id, "provider_id": self.provider_id, "tool_name": self.tool_name, "action": self.action, "args": self.args, "target": self.target, "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat(), "version": self.version, "binding_hash": self.binding_hash}

    def to_record(self) -> dict[str, Any]:
        return {**self.canonical(), "signer_kid": self.signer_kid, "signature_b64": self.signature_b64}


class SupabaseReplayStore:
    """Durable, tenant-scoped, atomic envelope replay ledger."""

    async def claim(self, *, tenant_id: UUID, envelope_id: str, expires_at: datetime, envelope_hash: str) -> bool:
        result = await supabase.rpc("claim_ai_execution_envelope", {
            "p_tenant_id": str(tenant_id),
            "p_envelope_id": envelope_id,
            "p_envelope_hash": envelope_hash,
            "p_expires_at": expires_at.isoformat(),
        })
        return bool(result)

class AgentExecutionDenied(RuntimeError):
    pass

class AgentExecutionGate:
    """Fail-closed boundary between AI intent and destructive response dispatch."""
    def __init__(self, replay_store: ReplayStore, policy: ToolPolicyEngine | None = None) -> None:
        self.replay_store = replay_store
        self.policy = policy or ToolPolicyEngine()

    @staticmethod
    def _envelope_hash(envelope: AgentEnvelope) -> str:
        return hashlib.sha256(json.dumps(envelope.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()

    async def validate(
        self,
        *,
        envelope: AgentEnvelope,
        tenant_id: UUID,
        expected_model_id: str,
        expected_provider_id: str,
        twin: DigitalTwinService,
        expected_mission_id: str | None = None,
        expected_mission_version: int | None = None,
        expected_mission_hash: str | None = None,
    ) -> dict[str, Any]:
        """Validate an envelope and simulate it without consuming replay state."""
        now = datetime.now(UTC)
        if envelope.tenant_id != tenant_id:
            raise AgentExecutionDenied("envelope tenant mismatch")
        if envelope.expires_at <= now or envelope.issued_at > now:
            raise AgentExecutionDenied("envelope expired or issued in the future")
        if envelope.model_id != expected_model_id:
            raise AgentExecutionDenied("model binding mismatch")
        if envelope.provider_id != expected_provider_id:
            raise AgentExecutionDenied("provider binding mismatch")
        if (expected_mission_id, expected_mission_version, expected_mission_hash) != (envelope.mission_id, envelope.mission_version, envelope.mission_hash):
            raise AgentExecutionDenied("mission binding mismatch")
        if not envelope.mission_id or envelope.mission_version is None or not envelope.mission_hash:
            raise AgentExecutionDenied("mission binding missing")
        if len(envelope.mission_hash) != 64 or any(c not in "0123456789abcdef" for c in envelope.mission_hash):
            raise AgentExecutionDenied("invalid mission hash")
        if not envelope.envelope_id or len(envelope.envelope_id) > 128:
            raise AgentExecutionDenied("invalid envelope id")
        if envelope.version != "1":
            raise AgentExecutionDenied("unsupported envelope version")
        if len(envelope.binding_hash) != 64 or any(c not in "0123456789abcdef" for c in envelope.binding_hash):
            raise AgentExecutionDenied("invalid provider binding hash")
        if not envelope.tool_name or not envelope.action or envelope.tool_name != envelope.action:
            raise AgentExecutionDenied("tool/action binding mismatch")
        digest = hashlib.sha256(
            json.dumps(
                envelope.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()
        if not await verify_digest_signature(digest, envelope.signature_b64, envelope.signer_kid):
            raise AgentExecutionDenied("invalid envelope signature")
        policy = await self.policy.check(tenant_id, envelope.agent_id, envelope.tool_name, envelope.args)
        if not policy.get("allowed") and not policy.get("requires_approval"):
            raise AgentExecutionDenied(str(policy.get("reason") or "tool policy denied"))
        simulation = await twin.simulate(envelope.target, envelope.action, envelope.args)
        return {
            "authorized": True,
            "requires_approval": bool(policy.get("requires_approval")),
            "envelope_id": envelope.envelope_id,
            "simulation_id": simulation["simulation_id"],
            "impact_score": simulation["impact_score"],
            "recommendation": simulation["recommendation"],
            "mission_id": envelope.mission_id,
            "mission_version": envelope.mission_version,
            "mission_hash": envelope.mission_hash,
        }

    async def consume(self, *, envelope: AgentEnvelope, tenant_id: UUID) -> None:
        """Consume an envelope exactly once after all approval gates pass."""
        now = datetime.now(UTC)
        if envelope.tenant_id != tenant_id:
            raise AgentExecutionDenied("envelope tenant mismatch")
        if envelope.expires_at <= now:
            raise AgentExecutionDenied("envelope expired")
        if not await self.replay_store.claim(
            tenant_id=tenant_id,
            envelope_id=envelope.envelope_id,
            expires_at=envelope.expires_at,
            envelope_hash=self._envelope_hash(envelope),
        ):
            raise AgentExecutionDenied("envelope replay detected")

    async def authorize(
        self,
        *,
        envelope: AgentEnvelope,
        tenant_id: UUID,
        expected_model_id: str,
        expected_provider_id: str,
        twin: DigitalTwinService,
        consume_replay: bool = True,
    ) -> dict[str, Any]:
        """Validate and optionally consume replay state for immediate execution."""
        result = await self.validate(
            envelope=envelope,
            tenant_id=tenant_id,
            expected_model_id=expected_model_id,
            expected_provider_id=expected_provider_id,
            twin=twin,
        )
        if consume_replay:
            await self.consume(envelope=envelope, tenant_id=tenant_id)
        return result
