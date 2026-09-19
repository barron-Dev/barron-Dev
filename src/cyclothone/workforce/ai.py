from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.storage.supabase_client import supabase
from cyclothone.workforce.auth import WorkforcePrincipal


@dataclass(frozen=True, slots=True)
class WorkforceAITurnAuthority:
    turn_id: UUID
    employee_id: UUID
    tenant_id: UUID
    mission_id: UUID
    mission_version: int
    mission_hash: str
    sequence_no: int


@dataclass(frozen=True, slots=True)
class WorkforceAIRunAuthority:
    run_id: UUID
    tenant_id: UUID
    mission_id: str
    mission_version: int
    mission_hash: str
    agent_id: UUID
    agent_version: int
    model_id: str
    model_version: int
    provider_id: str
    provider_binding_version: int


async def start_workforce_ai_run(
    principal: WorkforcePrincipal,
    turn_id: UUID,
    idempotency_token: str,
    trace_id: str | None = None,
    correlation_id: str | None = None,
) -> WorkforceAIRunAuthority:
    if not idempotency_token or len(idempotency_token.strip()) > 128:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid AI run idempotency token")

    client = await supabase._ensure()
    try:
        result = await client.schema("workforce").rpc(
            "start_ai_turn_run",
            {
                "p_user_id": principal.user_id,
                "p_turn_id": str(turn_id),
                "p_idempotency_token": idempotency_token.strip(),
                "p_trace_id": trace_id,
                "p_correlation_id": correlation_id,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI run authority unavailable",
        ) from exc

    row = result.data if isinstance(result.data, dict) else None
    if not row:
        raise HTTPException(status_code=503, detail="workforce AI run authority returned incomplete state")

    if row.get("tenant_id") is None:
        raise HTTPException(status_code=503, detail="workforce AI run authority returned invalid state")

    return WorkforceAIRunAuthority(
        run_id=UUID(str(row["id"])),
        tenant_id=UUID(str(row["tenant_id"])),
        mission_id=str(row["mission_id"]),
        mission_version=int(row["mission_version"]),
        mission_hash=str(row["mission_hash"]),
        agent_id=UUID(str(row["agent_id"])),
        agent_version=int(row["agent_version"]),
        model_id=str(row["model_id"]),
        model_version=int(row["model_version"]),
        provider_id=str(row["provider_id"]),
        provider_binding_version=int(row["provider_binding_version"]),
    )


async def admit_workforce_ai_turn(
    principal: WorkforcePrincipal,
    session_id: UUID,
    input_text: str,
    sequence_no: int,
) -> WorkforceAITurnAuthority:
    if not input_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AI input is required")
    if sequence_no < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid AI turn sequence")

    input_hash = sha256(input_text.encode("utf-8")).hexdigest()

    client = await supabase._ensure()
    try:
        result = await client.schema("workforce").rpc(
            "admit_ai_turn",
            {
                "p_user_id": principal.user_id,
                "p_session_id": str(session_id),
                "p_input_hash": input_hash,
                "p_sequence_no": sequence_no,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI turn authority unavailable",
        ) from exc

    rows = result.data or []
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI turn denied",
        )

    row = rows[0]
    if not bool(row.get("allowed")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "workforce_ai_turn_denied",
                "reason": row.get("reason", "ai_turn_not_authorized"),
            },
        )

    if str(row.get("employee_id")) != principal.employee_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce principal mismatch",
        )

    required = ("turn_id", "tenant_id", "mission_id", "mission_version", "mission_hash")
    if any(row.get(key) is None for key in required):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI turn authority returned incomplete state",
        )

    return WorkforceAITurnAuthority(
        turn_id=UUID(str(row["turn_id"])),
        employee_id=UUID(str(row["employee_id"])),
        tenant_id=UUID(str(row["tenant_id"])),
        mission_id=UUID(str(row["mission_id"])),
        mission_version=int(row["mission_version"]),
        mission_hash=str(row["mission_hash"]),
        sequence_no=sequence_no,
    )


async def complete_workforce_ai_turn(
    principal: WorkforcePrincipal,
    turn_id: UUID,
    output_text: str,
    outcome: str = "completed",
) -> bool:
    if not output_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AI output is required")
    if outcome not in {"completed", "rejected", "failed"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid AI turn outcome")

    output_hash = sha256(output_text.encode("utf-8")).hexdigest()
    client = await supabase._ensure()

    try:
        result = await client.schema("workforce").rpc(
            "complete_ai_turn",
            {
                "p_turn_id": str(turn_id),
                "p_output_hash": output_hash,
                "p_status": outcome,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI turn completion authority unavailable",
        ) from exc

    if result.data is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce AI turn completion denied",
        )

    # The database function verifies the employee attached to the turn is
    # still active. The authenticated principal must also be the same employee.
    try:
        turn = await (
            client.schema("workforce")
            .table("ai_turns")
            .select("employee_id")
            .eq("id", str(turn_id))
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce AI turn state unavailable",
        ) from exc

    rows = turn.data or []
    if not rows or str(rows[0]["employee_id"]) != principal.employee_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce principal mismatch",
        )

    return True
