from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from cyclothone.chauliodus.engine import ChauliodusEngine
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request

router = APIRouter(prefix="/chauliodus", tags=["chauliodus"])


class AttributeRequest(BaseModel):
    number: str = Field(min_length=4, max_length=32)
    case_id: UUID | None = None


def _require(principal: DeveloperPrincipal, scope: str) -> None:
    principal.require((scope,))


@router.post("/attribute")
async def attribute(body: AttributeRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    _require(principal, "chauliodus:attribute")
    try:
        result = await ChauliodusEngine(UUID(principal.tenant_id), None).attribute(body.number, body.case_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        status = 429 if "rate limit" in str(exc) else 503
        raise HTTPException(status, str(exc)) from exc
    return result


@router.get("/numbers")
async def list_numbers(min_fraud: float = Query(.5, ge=0, le=1), limit: int = Query(100, ge=1, le=500),
                       principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("chauliodus:read",))
    from cyclothone.storage.supabase_client import supabase
    async def _do():
        return await (await supabase._ensure()).table("chauliodus_numbers").select(
            "id,e164_hash,country,line_type,carrier,voip_probability,recycling_score,fraud_score,last_seen"
        ).eq("tenant_id", principal.tenant_id).gte("fraud_score", min_fraud).order("fraud_score", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do)).data or [])


@router.get("/attributions")
async def list_attributions(limit: int = Query(50, ge=1, le=200),
                            principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("chauliodus:read",))
    from cyclothone.storage.supabase_client import supabase
    async def _do():
        return await (await supabase._ensure()).table("chauliodus_attributions").select(
            "id,input_kind,input_hash,status,confidence,duration_ms,created_at"
        ).eq("tenant_id", principal.tenant_id).order("created_at", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do)).data or [])
