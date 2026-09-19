from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class ResponseExecutionAuthority:
    run_id: UUID
    security_decision_id: int
    execution_config_hash: str
    admission_hash: str | None
    envelope_id: str | None
    envelope_hash: str | None


def response_action_hash(
    *,
    action: str,
    args: dict[str, Any],
    target: str | None,
) -> str:
    payload = {
        "action": action,
        "args": args,
        "target": target,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


async def create_response_execution_approval(
    *,
    run_id: UUID,
    approval_ref: str,
    action_hash: str,
    risk_level: str,
    approver: UUID,
    expires_at: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    client = await supabase._ensure()
    try:
        result = await client.rpc(
            "ai_create_execution_approval",
            {
                "p_run_id": str(run_id),
                "p_approval_ref": approval_ref,
                "p_action_hash": action_hash,
                "p_risk_level": risk_level,
                "p_approver": str(approver),
                "p_expires_at": expires_at,
                "p_metadata": metadata or {},
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="execution approval authority unavailable",
        ) from exc
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="execution approval authority returned incomplete state",
        )
    return result.data if isinstance(result.data, dict) else {"approval": result.data}


async def authorize_response_execution(
    *,
    run_id: UUID,
    risk_level: str,
    destructive: bool,
    estimated_cost_usd: Decimal,
    execution_config: dict[str, Any],
    approval_ref: str | None = None,
    action_hash: str | None = None,
    actor: str = "response_orchestrator",
    lease_seconds: int = 600,
    envelope_id: str | None = None,
    envelope_hash: str | None = None,
    envelope_expires_at: str | None = None,
) -> ResponseExecutionAuthority:
    if not execution_config:
        raise HTTPException(status_code=400, detail="execution configuration is required")
    if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="invalid execution risk")
    if estimated_cost_usd < 0:
        raise HTTPException(status_code=400, detail="invalid execution cost")
    if lease_seconds < 30 or lease_seconds > 3600:
        raise HTTPException(status_code=400, detail="invalid execution lease")
    if destructive and (not approval_ref or not action_hash):
        raise HTTPException(status_code=400, detail="destructive execution approval context is required")

    client = await supabase._ensure()
    try:
        result = await client.rpc(
            "ai_execute_run",
            {
                "p_run_id": str(run_id),
                "p_risk_level": risk_level,
                "p_destructive": destructive,
                "p_estimated_cost_usd": str(estimated_cost_usd),
                "p_execution_config": execution_config,
                "p_approval_ref": approval_ref,
                "p_action_hash": action_hash,
                "p_actor": actor,
                "p_lease_seconds": lease_seconds,
                "p_envelope_id": envelope_id,
                "p_envelope_hash": envelope_hash,
                "p_envelope_expires_at": envelope_expires_at,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="canonical response execution authority unavailable",
        ) from exc

    row = result.data if isinstance(result.data, dict) else None
    if not row:
        raise HTTPException(status_code=503, detail="canonical execution authority returned incomplete state")
    if row.get("allowed") is not True:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "response_execution_denied",
                "reason": row.get("reason_code", "execution_denied"),
                "decision": row.get("decision"),
                "approval_required": row.get("approval_required", False),
            },
        )
    if row.get("committed") is not True:
        raise HTTPException(status_code=503, detail="canonical execution commit was not established")

    return ResponseExecutionAuthority(
        run_id=run_id,
        security_decision_id=int(row["security_decision_id"]),
        execution_config_hash=str(row["execution_config_hash"]),
        admission_hash=row.get("admission_hash"),
        envelope_id=row.get("envelope_id"),
        envelope_hash=row.get("envelope_hash"),
    )
