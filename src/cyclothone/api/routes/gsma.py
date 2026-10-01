from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from cyclothone.api.deps import get_principal, require_role
from cyclothone.gsma.integration import GSMAIntegration
from cyclothone.robotics.mcp_guard import MCPGuard
from cyclothone.robotics.sros2_audit import SROS2Auditor
from cyclothone.security.jwt import Principal
from cyclothone.storage.supabase_client import supabase

router=APIRouter()

@router.get("/operators")
async def list_operators(principal:Principal=Depends(get_principal)):
    async def load():
        c=await supabase._ensure()
        return await c.table("gsma_operators").select("id,name,country,mcc_mnc,enabled").eq("enabled",True).execute()
    return list((await supabase._retry(load)).data or [])

@router.post("/enrich")
async def enrich(number:str=Query(min_length=4,max_length=32),
                 latitude:float|None=Query(default=None,ge=-90,le=90),
                 longitude:float|None=Query(default=None,ge=-180,le=180),
                 principal:Principal=Depends(require_role("owner","admin","member"))):
    try: return await GSMAIntegration(principal.tenant_id).enrich(number,latitude,longitude)
    except RuntimeError as exc: raise HTTPException(502,str(exc)) from exc

@router.get("/signals")
async def list_signals(e164_hash:str|None=None,limit:int=Query(default=100,ge=1,le=500),
                       principal:Principal=Depends(get_principal)):
    async def load():
        c=await supabase._ensure()
        q=c.table("gsma_signals").select("id,e164_hash,signal_type,operator_id,confidence,risk_delta,observed_at").eq("tenant_id",str(principal.tenant_id)).order("observed_at",desc=True).limit(limit)
        if e164_hash: q=q.eq("e164_hash",e164_hash)
        return await q.execute()
    return list((await supabase._retry(load)).data or [])

