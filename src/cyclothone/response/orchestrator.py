from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer, EnvelopeIssueRequest
from cyclothone.ai.execution_gate import AgentEnvelope, AgentExecutionGate

logger = logging.getLogger(__name__)


class ActionClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


ACTION_CLASS: dict[str, ActionClass] = {
    "scan_now": ActionClass.LOW,
    "collect_forensics": ActionClass.LOW,
    "kill_process": ActionClass.MEDIUM,
    "block_hash": ActionClass.MEDIUM,
    "block_ip": ActionClass.MEDIUM,
    "quarantine_file": ActionClass.MEDIUM,
    "restore_file": ActionClass.MEDIUM,
    "rollback": ActionClass.MEDIUM,
    "isolate_host": ActionClass.HIGH,
    "release_host": ActionClass.HIGH,
    "force_logout": ActionClass.HIGH,
    "disable_account": ActionClass.CRITICAL,
}


@dataclass(frozen=True, slots=True)
class ActionPlan:
    action: str
    args: dict[str, Any]
    requires_approval: bool = False
    rollback: dict[str, Any] | None = None
    agent_envelope: AgentEnvelope | None = None  # persisted/internal only; never accepted as execution input
    envelope_request: EnvelopeIssueRequest | None = None
    model_id: str | None = None
    provider_id: str | None = None
    target: str | None = None
    mission_id: str | None = None
    mission_version: int | None = None
    mission_hash: str | None = None


@dataclass(frozen=True, slots=True)
class ChainResult:
    case_id: str
    dispatched: list[str]
    queued: list[str]
    rejected: list[str]
    reasons: dict[str, str]


class Dispatcher(Protocol):
    async def issue(self, *, tenant_id: UUID, device_id: UUID | None, action: str, args: dict[str, Any], issued_by: str, case_action_id: UUID | None = None, execution_context: dict[str, Any] | None = None) -> dict[str, Any]: ...


class ActionStore(Protocol):
    async def create(self, **values: Any) -> str: ...
    async def get(self, action_id: UUID) -> dict[str, Any] | None: ...
    async def update(self, action_id: UUID, **values: Any) -> None: ...
    async def blast_allowed(self, rule_id: UUID, limit: int, window_minutes: int = 60, tenant_id: UUID | None = None, device_id: UUID | None = None) -> bool: ...
    async def record_blast(self, *, rule_id: UUID, tenant_id: UUID, device_id: UUID, case_id: UUID) -> None: ...


class Signer(Protocol):
    def sign(self, payload: dict[str, Any]) -> Any: ...


class ResponseOrchestrator:
    """Single owner of case response execution and safety gates."""

    @staticmethod
    def _envelope_hash(envelope: AgentEnvelope | None) -> str | None:
        if envelope is None:
            return None
        encoded = json.dumps(envelope.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _execution_context(cls, step: ActionPlan, case_action_id: str | None = None) -> dict[str, Any]:
        args_encoded = json.dumps(step.args, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return {
            "case_action_id": case_action_id,
            "agent_id": str(step.agent_envelope.agent_id) if step.agent_envelope else None,
            "model_id": step.model_id,
            "provider_id": step.provider_id,
            "tool_name": step.agent_envelope.tool_name if step.agent_envelope else step.action,
            "target": step.target,
            "envelope_id": step.agent_envelope.envelope_id if step.agent_envelope else None,
            "envelope_hash": cls._envelope_hash(step.agent_envelope),
            "args_hash": hashlib.sha256(args_encoded).hexdigest(),
            "mission_id": step.agent_envelope.mission_id if step.agent_envelope else step.mission_id,
            "mission_version": step.agent_envelope.mission_version if step.agent_envelope else step.mission_version,
            "mission_hash": step.agent_envelope.mission_hash if step.agent_envelope else step.mission_hash,
        }

    def __init__(self, dispatcher: Dispatcher, store: ActionStore, signer: Signer | None = None, execution_gate: AgentExecutionGate | None = None, envelope_issuer: AIEnvelopeIssuer | None = None) -> None:
        self.dispatcher = dispatcher
        self.store = store
        self.signer = signer
        self.execution_gate = execution_gate
        self.envelope_issuer = envelope_issuer

    async def run_chain(
        self, *, tenant_id: UUID, case_id: UUID, device_id: UUID | None,
        plan: list[ActionPlan], issued_by: str, initiated_by_rule: UUID | None = None,
        dry_run: bool = False, blast_rule_id: UUID | None = None, blast_limit: int = 10,
    ) -> ChainResult:
        dispatched: list[str] = []
        queued: list[str] = []
        rejected: list[str] = []
        reasons: dict[str, str] = {}

        for step in plan:
            row_id = ""
            try:
                if not step.action.strip():
                    raise ValueError("action must not be empty")
                action_class = ACTION_CLASS.get(step.action, ActionClass.MEDIUM)
                approval_required = step.requires_approval or action_class in (ActionClass.HIGH, ActionClass.CRITICAL)

                if action_class in (ActionClass.MEDIUM, ActionClass.HIGH, ActionClass.CRITICAL):
                    if self.execution_gate is None or self.envelope_issuer is None:
                        raise RuntimeError("authoritative AI envelope issuer and execution gate are required for destructive response actions")
                    if step.envelope_request is None:
                        raise RuntimeError("destructive response requires an envelope issuance request")
                    request = step.envelope_request
                    if request.tenant_id != tenant_id or request.action != step.action or request.args != step.args:
                        raise RuntimeError("envelope issuance request does not match response plan")
                    if step.model_id and request.model_id != step.model_id:
                        raise RuntimeError("envelope request model mismatch")
                    if step.provider_id and request.provider_id != step.provider_id:
                        raise RuntimeError("envelope request provider mismatch")
                    if step.target and request.target != step.target:
                        raise RuntimeError("envelope request target mismatch")
                    if step.mission_id and request.mission_id != step.mission_id:
                        raise RuntimeError("envelope request mission mismatch")
                    if step.mission_version is not None and request.mission_version != step.mission_version:
                        raise RuntimeError("envelope request mission version mismatch")
                    if step.mission_hash and request.mission_hash != step.mission_hash:
                        raise RuntimeError("envelope request mission hash mismatch")
                    step_envelope = await self.envelope_issuer.issue(request)
                    from cyclothone.twin.service import DigitalTwinService
                    await self.execution_gate.validate(
                        envelope=step_envelope,
                        tenant_id=tenant_id,
                        expected_model_id=request.model_id,
                        expected_provider_id=request.provider_id,
                        twin=DigitalTwinService(tenant_id),
                    )
                    if not approval_required and not dry_run:
                        await self.execution_gate.consume(envelope=step_envelope, tenant_id=tenant_id)
                    step = ActionPlan(
                        action=step.action, args=step.args, requires_approval=step.requires_approval,
                        rollback=step.rollback, agent_envelope=step_envelope, envelope_request=request,
                        model_id=request.model_id, provider_id=request.provider_id, target=request.target,
                    )

                if blast_rule_id and device_id and not await self.store.blast_allowed(blast_rule_id, blast_limit, tenant_id=tenant_id, device_id=device_id):
                    row_id = await self.store.create(
                        tenant_id=tenant_id, case_id=case_id, device_id=device_id,
                        action=step.action, args=step.args, status="rejected",
                        issued_by=issued_by, initiated_by_rule=initiated_by_rule,
                        rollback_args=step.rollback, error="blast radius exceeded",
                    )
                    rejected.append(row_id)
                    reasons[row_id] = "blast radius exceeded"
                    continue

                if approval_required and not dry_run:
                    row_id = await self.store.create(
                        tenant_id=tenant_id, case_id=case_id, device_id=device_id,
                        action=step.action, args=step.args, status="pending_approval",
                        issued_by=issued_by, initiated_by_rule=initiated_by_rule,
                        rollback_args=step.rollback,
                        agent_envelope=step.agent_envelope.to_record() if step.agent_envelope else None,
                        ai_agent_id=str(step.agent_envelope.agent_id) if step.agent_envelope else None,
                        ai_model_id=step.model_id, ai_provider_id=step.provider_id,
                        ai_tool_name=step.agent_envelope.tool_name if step.agent_envelope else None,
                        ai_target=step.target,
                        ai_envelope_id=step.agent_envelope.envelope_id if step.agent_envelope else None,
                        ai_envelope_hash=self._envelope_hash(step.agent_envelope),
                        ai_args_hash=self._execution_context(step)["args_hash"],
                        model_id=step.model_id, provider_id=step.provider_id, target=step.target,
                    )
                    queued.append(row_id)
                    continue

                if dry_run:
                    row_id = await self.store.create(
                        tenant_id=tenant_id, case_id=case_id, device_id=device_id,
                        action=step.action, args=step.args, status="approved",
                        issued_by=issued_by, initiated_by_rule=initiated_by_rule,
                        rollback_args=step.rollback, error="dry run: not dispatched",
                    )
                    dispatched.append(row_id)
                    continue

                row_id = await self._dispatch_step(tenant_id, case_id, device_id, step, issued_by, initiated_by_rule)
                dispatched.append(row_id)
                if blast_rule_id and device_id:
                    await self.store.record_blast(rule_id=blast_rule_id, tenant_id=tenant_id, device_id=device_id, case_id=case_id)
            except Exception as exc:
                logger.exception("response chain step failed")
                if not row_id:
                    row_id = await self.store.create(
                        tenant_id=tenant_id, case_id=case_id, device_id=device_id,
                        action=step.action, args=step.args, status="failed",
                        issued_by=issued_by, initiated_by_rule=initiated_by_rule,
                        rollback_args=step.rollback, error=str(exc)[:500],
                    )
                else:
                    await self.store.update(UUID(row_id), status="failed", error=str(exc)[:500])
                rejected.append(row_id)
                reasons[row_id] = str(exc)[:500]

        return ChainResult(str(case_id), dispatched, queued, rejected, reasons)

    async def approve(self, case_action_id: UUID, approved_by: UUID) -> dict[str, Any]:
        row = await self.store.get(case_action_id)
        if not row:
            raise RuntimeError("case_action not found")
        if row.get("status") != "pending_approval":
            raise RuntimeError(f"case_action {case_action_id} is {row.get('status')}")
        rule_id = UUID(str(row["initiated_by_rule"])) if row.get("initiated_by_rule") else None
        device_id = UUID(str(row["device_id"])) if row.get("device_id") else None
        if rule_id and device_id and not await self.store.blast_allowed(rule_id, 10, tenant_id=UUID(str(row["tenant_id"])), device_id=device_id):
            await self.store.update(case_action_id, status="rejected", rejected_by=str(approved_by), rejected_at=datetime.now(timezone.utc).isoformat(), rejection_reason="blast radius exceeded")
            raise RuntimeError("blast radius exceeded")
        command = None
        try:
            envelope_data = row.get("agent_envelope")
            if not envelope_data:
                raise RuntimeError("approved destructive action is missing its signed agent envelope")
            if isinstance(envelope_data, dict):
                envelope = AgentEnvelope(
                    envelope_id=str(envelope_data["envelope_id"]), tenant_id=UUID(str(envelope_data["tenant_id"])),
                    agent_id=UUID(str(envelope_data["agent_id"])), model_id=str(envelope_data["model_id"]),
                    provider_id=str(envelope_data["provider_id"]), tool_name=str(envelope_data["tool_name"]),
                    action=str(envelope_data["action"]), args=envelope_data.get("args") or {}, target=str(envelope_data["target"]),
                    issued_at=datetime.fromisoformat(str(envelope_data["issued_at"])),
                    expires_at=datetime.fromisoformat(str(envelope_data["expires_at"])),
                    signer_kid=str(envelope_data["signer_kid"]), signature_b64=str(envelope_data["signature_b64"]),
                    version=str(envelope_data.get("version") or "1"), binding_hash=str(envelope_data.get("binding_hash") or ""),
                )
            else:
                envelope = None
            if envelope is None:
                raise RuntimeError("invalid persisted agent envelope")
            if self.execution_gate is None:
                raise RuntimeError("AI execution gate is required for destructive approval")
            action_class = ACTION_CLASS.get(row["action"], ActionClass.MEDIUM)
            if action_class in (ActionClass.MEDIUM, ActionClass.HIGH, ActionClass.CRITICAL):
                await self.execution_gate.validate(
                    envelope=envelope,
                    tenant_id=UUID(str(row["tenant_id"])),
                    expected_model_id=str(row.get("model_id") or ""),
                    expected_provider_id=str(row.get("provider_id") or ""),
                    twin=__import__("cyclothone.twin.service", fromlist=["DigitalTwinService"]).DigitalTwinService(UUID(str(row["tenant_id"]))),
                )
                await self.execution_gate.consume(
                    envelope=envelope,
                    tenant_id=UUID(str(row["tenant_id"])),
                )
            execution_context = {
                "case_action_id": str(case_action_id),
                "agent_id": str(envelope.agent_id),
                "model_id": envelope.model_id,
                "provider_id": envelope.provider_id,
                "tool_name": envelope.tool_name,
                "target": envelope.target,
                "envelope_id": envelope.envelope_id,
                "envelope_hash": self._envelope_hash(envelope),
                "args_hash": hashlib.sha256(json.dumps(row.get("args") or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest(),
            }
            command = await self.dispatcher.issue(
                tenant_id=UUID(str(row["tenant_id"])), device_id=UUID(str(row["device_id"])) if row.get("device_id") else None,
                action=row["action"], args=row.get("args") or {}, issued_by=f"approval:{approved_by}",
                case_action_id=case_action_id, execution_context=execution_context,
            )
            await self.store.update(case_action_id, status="dispatched", command_id=command["id"], dispatched_at=datetime.now(timezone.utc).isoformat())
            if rule_id and device_id:
                await self.store.record_blast(rule_id=rule_id, tenant_id=UUID(str(row["tenant_id"])), device_id=device_id, case_id=UUID(str(row["case_id"])))
            return {"case_action_id": str(case_action_id), "command_id": command["id"]}
        except Exception:
            await self.store.update(case_action_id, status="pending_approval", approved_by=None, approved_at=None)
            raise

    async def reject(self, case_action_id: UUID, rejected_by: UUID, reason: str) -> dict[str, Any]:
        row = await self.store.get(case_action_id)
        if not row:
            raise RuntimeError("case_action not found")
        if row.get("status") != "pending_approval":
            raise RuntimeError(f"case_action {case_action_id} is {row.get('status')}")
        await self.store.update(case_action_id, status="rejected", rejected_by=str(rejected_by), rejected_at=datetime.now(timezone.utc).isoformat(), rejection_reason=reason[:500])
        return {"case_action_id": str(case_action_id), "status": "rejected"}

    async def _dispatch_step(self, tenant_id: UUID, case_id: UUID, device_id: UUID | None, step: ActionPlan, issued_by: str, rule_id: UUID | None) -> str:
        row_id = await self.store.create(
            tenant_id=tenant_id, case_id=case_id, device_id=device_id,
            action=step.action, args=step.args, status="approved", issued_by=issued_by,
            initiated_by_rule=rule_id, rollback_args=step.rollback,
            ai_agent_id=str(step.agent_envelope.agent_id) if step.agent_envelope else None,
            ai_model_id=step.model_id, ai_provider_id=step.provider_id,
            ai_tool_name=step.agent_envelope.tool_name if step.agent_envelope else step.action,
            ai_target=step.target,
            ai_envelope_id=step.agent_envelope.envelope_id if step.agent_envelope else None,
            ai_envelope_hash=self._envelope_hash(step.agent_envelope),
            ai_args_hash=self._execution_context(step)["args_hash"],
        )
        if self.signer:
            signed = self.signer.sign({
                "case_action_id": row_id, "action": step.action, "args": step.args,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            await self.store.update(row_id, signature=signed.signature_b64, signer_kid=signed.kid)
        command = await self.dispatcher.issue(
            tenant_id=tenant_id, device_id=device_id, action=step.action, args=step.args,
            issued_by=issued_by, case_action_id=UUID(row_id),
            execution_context=self._execution_context(step, row_id),
        )
        await self.store.update(UUID(row_id), status="dispatched", command_id=command["id"], dispatched_at=datetime.now(timezone.utc).isoformat())
        return row_id
