from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cyclothone.storage.supabase_client import supabase
from cyclothone.workforce.ai import WorkforceAITurnAuthority, admit_workforce_ai_turn
from cyclothone.workforce.execution import (
    WorkforceAIExecutionAuthority,
    authorize_workforce_ai_execution,
    complete_workforce_ai_execution,
)
from cyclothone.workforce.auth import WorkforcePrincipal, authenticate_workforce_request

router = APIRouter(prefix="/workforce/ai", tags=["workforce-ai"])


class AISessionRequest(BaseModel):
    tenant_id: UUID
    mission_id: UUID
    mission_version: int = Field(gt=0)
    mission_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AISessionResponse(BaseModel):
    session_id: UUID
    employee_id: UUID
    tenant_id: UUID
    mission_assignment_id: UUID
    mission_id: UUID
    mission_version: int
    mission_hash: str
    expires_at: str


@router.post("/sessions", response_model=AISessionResponse)
async def create_ai_session(
    request: AISessionRequest,
    principal: WorkforcePrincipal = Depends(authenticate_workforce_request),
) -> AISessionResponse:
    """
    Create a bounded internal-AI session.

    The request supplies only the exact mission identity. The database
    authorization boundary decides whether this employee may use it.
    """
    try:
        result = await supabase._ensure()
        rpc = await result.schema("workforce").rpc(
            "authorize_ai_session",
            {
                "p_user_id": principal.user_id,
                "p_tenant_id": str(request.tenant_id),
                "p_mission_id": str(request.mission_id),
                "p_mission_version": request.mission_version,
                "p_mission_hash": request.mission_hash,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI session authority unavailable",
        ) from exc

    rows = rpc.data or []
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI session denied",
        )

    row = rows[0]
    if not bool(row.get("allowed")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "workforce_ai_session_denied",
                "reason": row.get("reason", "ai_mission_not_authorized"),
            },
        )

    if str(row.get("employee_id")) != principal.employee_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce principal mismatch",
        )

    session_id = row.get("session_id")
    assignment_id = row.get("mission_assignment_id")
    if not session_id or not assignment_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI session authority returned incomplete state",
        )

    # Read the exact session from the private workforce schema.
    try:
        session_response = await (
            result.schema("workforce")
            .table("ai_sessions")
            .select("id,employee_id,tenant_id,expires_at")
            .eq("id", str(session_id))
            .eq("employee_id", principal.employee_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI session state unavailable",
        ) from exc

    sessions = session_response.data or []
    if not sessions:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI session state unavailable",
        )

    session = sessions[0]
    if str(session["tenant_id"]) != str(request.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI tenant mismatch",
        )

    return AISessionResponse(
        session_id=UUID(str(session["id"])),
        employee_id=UUID(str(principal.employee_id)),
        tenant_id=request.tenant_id,
        mission_assignment_id=UUID(str(assignment_id)),
        mission_id=request.mission_id,
        mission_version=request.mission_version,
        mission_hash=request.mission_hash,
        expires_at=str(session["expires_at"]),
    )



class AITurnRequest(BaseModel):
    input: str = Field(min_length=1)
    sequence_no: int = Field(ge=1)


class AITurnResponse(BaseModel):
    turn_id: UUID
    employee_id: UUID
    tenant_id: UUID
    mission_id: UUID
    mission_version: int
    mission_hash: str
    sequence_no: int


@router.post("/sessions/{session_id}/turns", response_model=AITurnResponse)
async def admit_ai_turn(
    session_id: UUID,
    request: AITurnRequest,
    principal: WorkforcePrincipal = Depends(authenticate_workforce_request),
) -> AITurnResponse:
    authority: WorkforceAITurnAuthority = await admit_workforce_ai_turn(
        principal=principal,
        session_id=session_id,
        input_text=request.input,
        sequence_no=request.sequence_no,
    )
    return AITurnResponse(
        turn_id=authority.turn_id,
        employee_id=authority.employee_id,
        tenant_id=authority.tenant_id,
        mission_id=authority.mission_id,
        mission_version=authority.mission_version,
        mission_hash=authority.mission_hash,
        sequence_no=authority.sequence_no,
    )


class AIExecutionRequest(BaseModel):
    run_id: UUID
    execution_config: dict
    risk_level: str = Field(pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    destructive: bool = False
    estimated_cost_usd: float = Field(default=0, ge=0)
    approval_ref: str | None = None
    action_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    actor: str = Field(default="workforce_ai", min_length=1, max_length=128)
    lease_seconds: int = Field(default=600, ge=30, le=3600)


class AIExecutionResponse(BaseModel):
    turn_id: UUID
    run_id: UUID
    security_decision_id: int
    execution_config_hash: str
    admission_hash: str | None = None
    envelope_id: str | None = None
    envelope_hash: str | None = None


@router.post("/turns/{turn_id}/execute", response_model=AIExecutionResponse)
async def authorize_ai_execution(
    turn_id: UUID,
    request: AIExecutionRequest,
    principal: WorkforcePrincipal = Depends(authenticate_workforce_request),
) -> AIExecutionResponse:
    authority: WorkforceAIExecutionAuthority = await authorize_workforce_ai_execution(
        principal=principal,
        turn_id=turn_id,
        run_id=request.run_id,
        execution_config=request.execution_config,
        risk_level=request.risk_level,
        destructive=request.destructive,
        estimated_cost_usd=request.estimated_cost_usd,
        approval_ref=request.approval_ref,
        action_hash=request.action_hash,
        actor=request.actor,
        lease_seconds=request.lease_seconds,
    )
    return AIExecutionResponse(
        turn_id=authority.turn_id,
        run_id=authority.run_id,
        security_decision_id=authority.security_decision_id,
        execution_config_hash=authority.execution_config_hash,
        admission_hash=authority.admission_hash,
        envelope_id=authority.envelope_id,
        envelope_hash=authority.envelope_hash,
    )


class AITurnCompletionRequest(BaseModel):
    output: str = Field(min_length=1)
    outcome: str = Field(default="completed", pattern=r"^(completed|rejected|failed)$")


@router.post("/turns/{turn_id}/complete", response_model=dict[str, bool])
async def complete_ai_turn(
    turn_id: UUID,
    request: AITurnCompletionRequest,
    principal: WorkforcePrincipal = Depends(authenticate_workforce_request),
) -> dict[str, bool]:
    await complete_workforce_ai_execution(
        principal=principal,
        turn_id=turn_id,
        output_text=request.output,
        outcome=request.outcome,
    )
    return {"completed": True}
