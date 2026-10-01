from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/console/devices", tags=["device-enrollment"])


def _write(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:write",))
    return principal


class CreateEnrollmentTokenRequest(BaseModel):
    expires_in_seconds: int = Field(default=3600, ge=300, le=86400)


@router.post("/enrollment-tokens", status_code=201)
async def create_enrollment_token(
    body: CreateEnrollmentTokenRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict[str, Any]:
    # The plaintext token exists only in this response; only its SHA-256 digest
    # is persisted by the service-role RPC.
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(seconds=body.expires_in_seconds)

    try:
        result = await supabase.rpc(
            "create_device_enrollment_token",
            {
                "p_app_id": principal.app_id,
                "p_token_hash": token_hash,
                "p_expires_at": expires_at.isoformat(),
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="enrollment token issuance unavailable",
        ) from exc

    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict) or not row.get("token_id"):
        raise HTTPException(
            status_code=503,
            detail="enrollment token issuance did not produce an identity",
        )

    return {
        "token": token,
        "token_id": str(row["token_id"]),
        "tenant_id": str(row["tenant_id"]),
        "expires_at": str(row["expires_at"]),
    }
