from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cyclothone.storage.supabase_client import supabase
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
