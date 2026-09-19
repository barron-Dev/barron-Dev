from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.storage.supabase_client import supabase
from cyclothone.workforce.auth import WorkforcePrincipal


@dataclass(frozen=True, slots=True)
class WorkforceAIExecutionAuthority:
    turn_id: UUID
    run_id: UUID
    security_decision_id: int
    execution_config_hash: str
    admission_hash: str | None
    envelope_id: str | None
    envelope_hash: str | None


async def authorize_workforce_ai_execution(
    principal: WorkforcePrincipal,
    *,
    turn_id: UUID,
    run_id: UUID,
    execution_config: dict[str, Any],
    risk_level: str,
    destructive: bool = False,
    estimated_cost_usd: float = 0,
    approval_ref: str | None = None,
    action_hash: str | None = None,
    actor: str = "workforce_ai",
    lease_seconds: int = 600,
) -> WorkforceAIExecutionAuthority:
    if not execution_config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="execution configuration is required",
        )
    if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid execution risk")
    if estimated_cost_usd < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid execution cost")
    if lease_seconds < 30 or lease_seconds > 3600:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid execution lease")

    client = await supabase._ensure()
    try:
        result = await client.schema("workforce").rpc(
            "authorize_ai_turn_execution",
            {
                "p_user_id": principal.user_id,
                "p_turn_id": str(turn_id),
                "p_run_id": str(run_id),
                "p_execution_config": execution_config,
                "p_risk_level": risk_level,
                "p_destructive": destructive,
                "p_estimated_cost_usd": estimated_cost_usd,
                "p_approval_ref": approval_ref,
                "p_action_hash": action_hash,
                "p_actor": actor,
                "p_lease_seconds": lease_seconds,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI execution authority unavailable",
        ) from exc

    row = result.data if isinstance(result.data, dict) else None
    if not row:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI execution authority returned incomplete state",
        )

    if row.get("allowed") is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "workforce_ai_execution_denied",
                "reason": row.get("reason_code", row.get("reason", "execution_denied")),
                "decision": row.get("decision"),
                "approval_required": row.get("approval_required", False),
            },
        )

    if row.get("committed") is not True:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="canonical AI execution commit was not established",
        )

    return WorkforceAIExecutionAuthority(
        turn_id=turn_id,
        run_id=UUID(str(row["run_id"])),
        security_decision_id=int(row["security_decision_id"]),
        execution_config_hash=str(row["execution_config_hash"]),
        admission_hash=row.get("admission_hash"),
        envelope_id=row.get("envelope_id"),
        envelope_hash=row.get("envelope_hash"),
    )


async def complete_workforce_ai_execution(
    principal: WorkforcePrincipal,
    *,
    turn_id: UUID,
    output_text: str,
    outcome: str = "completed",
    actual_cost_usd: float = 0,
) -> dict[str, Any]:
    if not output_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AI output is required")
    if outcome not in {"completed", "rejected", "failed"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid AI turn outcome")
    if actual_cost_usd < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid actual cost")

    output_hash = sha256(output_text.encode("utf-8")).hexdigest()
    client = await supabase._ensure()
    try:
        result = await client.schema("workforce").rpc(
            "complete_ai_turn_execution",
            {
                "p_user_id": principal.user_id,
                "p_turn_id": str(turn_id),
                "p_output_hash": output_hash,
                "p_status": outcome,
                "p_actual_cost_usd": actual_cost_usd,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI execution completion authority unavailable",
        ) from exc

    row = result.data if isinstance(result.data, dict) else None
    if not row or row.get("completed") is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI execution completion denied",
        )
    return row
