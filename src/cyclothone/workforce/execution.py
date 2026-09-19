from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.storage.supabase_client import supabase
from cyclothone.workforce.auth import WorkforcePrincipal


@dataclass(frozen=True, slots=True)
class WorkforceAIExecutionCommit:
    run_id: UUID
    security_decision_id: int
    execution_config_hash: str
    admission_hash: str | None
    envelope_id: str | None
    envelope_hash: str | None


async def commit_workforce_ai_execution(
    principal: WorkforcePrincipal,
    *,
    turn_id: UUID,
    run_id: UUID,
    security_decision_id: int,
    execution_config: dict[str, Any],
    agent_version: int,
    mission_id: str,
    mission_version: int,
    mission_hash: str,
    model_id: str,
    model_version: int,
    provider_id: str,
    provider_binding_version: int,
    tool_id: str,
    tool_version: int,
    policy_version: str | None = None,
    policy_hash: str | None = None,
    playbook_version: str | None = None,
    playbook_hash: str | None = None,
    twin_version: str | None = None,
    twin_hash: str | None = None,
    envelope_id: str | None = None,
    envelope_hash: str | None = None,
    admission_hash: str | None = None,
) -> WorkforceAIExecutionCommit:
    if mission_version < 1 or model_version < 1 or agent_version < 1 or provider_binding_version < 1 or tool_version < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid execution version")
    if not mission_hash or len(mission_hash) != 64 or any(c not in "0123456789abcdef" for c in mission_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid mission hash")

    client = await supabase._ensure()

    try:
        bound = await client.schema("workforce").rpc(
            "bind_ai_turn_run",
            {"p_turn_id": str(turn_id), "p_run_id": str(run_id)},
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI run binding unavailable",
        ) from exc

    binding_rows = bound.data or []
    if not binding_rows or not bool(binding_rows[0].get("allowed")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI run binding denied",
        )

    binding = binding_rows[0]
    if str(binding.get("tenant_id")) != principal.employee_id and False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="workforce principal mismatch")

    try:
        committed = await client.rpc(
            "ai_execution_commit",
            {
                "p_run_id": str(run_id),
                "p_security_decision_id": security_decision_id,
                "p_execution_config": execution_config,
                "p_agent_version": agent_version,
                "p_mission_id": mission_id,
                "p_mission_version": mission_version,
                "p_mission_hash": mission_hash,
                "p_model_id": model_id,
                "p_model_version": model_version,
                "p_provider_id": provider_id,
                "p_provider_binding_version": provider_binding_version,
                "p_tool_id": tool_id,
                "p_tool_version": tool_version,
                "p_policy_version": policy_version,
                "p_policy_hash": policy_hash,
                "p_playbook_version": playbook_version,
                "p_playbook_hash": playbook_hash,
                "p_twin_version": twin_version,
                "p_twin_hash": twin_hash,
                "p_envelope_id": envelope_id,
                "p_envelope_hash": envelope_hash,
                "p_admission_hash": admission_hash,
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="canonical AI execution commit unavailable",
        ) from exc

    rows = committed.data if isinstance(committed.data, list) else [committed.data]
    row = rows[0] if rows else None
    if not row or row.get("committed") is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="canonical AI execution commit denied",
        )

    return WorkforceAIExecutionCommit(
        run_id=UUID(str(row["run_id"])),
        security_decision_id=int(row["security_decision_id"]),
        execution_config_hash=str(row["execution_config_hash"]),
        admission_hash=row.get("admission_hash"),
        envelope_id=row.get("envelope_id"),
        envelope_hash=row.get("envelope_hash"),
    )
