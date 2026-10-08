from __future__ import annotations
import os
from uuid import UUID
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request

# CI contract marker: mobile-intelligence/copilot is authenticated before Copilot execution.
# authenticate_request is the canonical backend admission boundary.
from cyclothone.storage.supabase_client import supabase

router=APIRouter(prefix="/mobile-intelligence",tags=["mobile-intelligence"])

class CopilotRequest(BaseModel):
    thread_id: UUID
    message: str = Field(min_length=1,max_length=12000)
    case_id: UUID|None = None

@router.post("/copilot")
async def copilot(body: CopilotRequest, principal: DeveloperPrincipal=Depends(authenticate_request)):
    principal.require(("mobile_intelligence:read",))
    tenant_id=principal.tenant_id
    if not tenant_id:
        raise HTTPException(403,"workspace_not_admitted")
    thread=await supabase.select_one("mdi_copilot_threads","id,tenant_id,case_id",id=str(body.thread_id),tenant_id=tenant_id)
    if not thread:
        raise HTTPException(404,"copilot_thread_not_found")
    if body.case_id is not None:
        case=await supabase.select_one("crime_cases","id,tenant_id",id=str(body.case_id),tenant_id=tenant_id)
        if not case:
            raise HTTPException(404,"case_not_found")
        if thread.get("case_id") and str(thread["case_id"]) != str(body.case_id):
            raise HTTPException(409,"copilot_thread_case_mismatch")
    elif thread.get("case_id"):
        body_case_id=str(thread["case_id"])
    else:
        body_case_id=None
    url=(os.getenv("MDI_COPILOT_URL") or "").rstrip("/")
    token=os.getenv("MDI_COPILOT_INTERNAL_TOKEN")
    if not url or not token:
        raise HTTPException(503,"copilot_not_configured")
    payload={"tenant_id":tenant_id,"thread_id":str(body.thread_id),"user_id":str(principal.user_id),"message":body.message,"case_id":str(body.case_id) if body.case_id else body_case_id}
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            r=await client.post(url+"/ask",json=payload,headers={"Authorization":f"Bearer {token}"})
    except httpx.HTTPError as exc:
        raise HTTPException(502,"copilot_unavailable") from exc
    if r.status_code!=200:
        raise HTTPException(502,"copilot_failed")
    return r.json()
