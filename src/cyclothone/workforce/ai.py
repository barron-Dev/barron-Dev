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
