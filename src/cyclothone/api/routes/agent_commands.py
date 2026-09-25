from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cyclothone.security.device_auth import DeviceIdentity, get_device
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/agent/commands", tags=["agent-commands"])


class CommandResult(BaseModel):
    command_id: UUID
    status: str = Field(pattern="^(success|failed)$")
    result: dict[str, Any] | None = None
    error: str | None = Field(default=None, max_length=1000)


@router.get("")
async def poll_commands(limit: int = 10, device: DeviceIdentity = Depends(get_device)):
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit must be 1..50")
    try:
        rows = await supabase.rpc("claim_device_commands",
                                  {"p_device_id": device.device_id, "p_limit": limit})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="command queue unavailable") from exc
    return {"commands": [
        {k: row[k] for k in ("id","tenant_id","device_id","action","args","signature",
                             "signer_kid","issued_by","issued_at","expires_at",
                             "case_action_id")}
        for row in (rows or [])
    ]}


@router.post("/{command_id}/result")
async def report_command_result(command_id: UUID, body: CommandResult,
                                device: DeviceIdentity = Depends(get_device)):
    if body.command_id != command_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="command_id mismatch")
    try:
        settlement = await supabase.rpc("ai_complete_device_command_result", {
            "p_device_id": str(device.device_id),
            "p_command_id": str(command_id),
            "p_status": body.status,
            "p_result": body.result,
            "p_error": body.error,
            "p_actor": f"device:{device.device_id}",
        })
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="command execution completion authority unavailable",
        ) from exc

    row = settlement[0] if isinstance(settlement, list) and settlement else settlement
    if not row:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="command completion was not accepted",
        )

    return row
