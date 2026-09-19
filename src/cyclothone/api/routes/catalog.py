from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from cyclothone.api.deps import get_principal, require_role
from cyclothone.global_catalog.loader import catalog
from cyclothone.security.jwt import Principal
from cyclothone.storage.supabase_client import supabase

router=APIRouter()

async def _catalog(fn):
    principal=get_principal
    return await fn()

@router.get("/regions")
async def regions(_: Principal=Depends(get_principal)): return await catalog.regions()
@router.get("/frameworks")
async def frameworks(_: Principal=Depends(get_principal)): return await catalog.frameworks()
@router.get("/regulators")
async def regulators(_: Principal=Depends(get_principal)): return await catalog.regulators()
@router.get("/certs")
async def certs(_: Principal=Depends(get_principal)): return await catalog.certs()
@router.get("/isacs")
async def isacs(_: Principal=Depends(get_principal)): return await catalog.isacs()
@router.get("/operators")
async def operators(_: Principal=Depends(get_principal)): return await catalog.operators()
@router.get("/channels")
async def channels(_: Principal=Depends(get_principal)): return await catalog.channels()

class PrefsUpdate(BaseModel):
    default_locale:str=Field(pattern=r"^[a-z]{2}(-[A-Z]{2})?$")
    default_region:str=Field(pattern=r"^[A-Z]{2}$")
    timezone:str=Field(max_length=64)
    country:str=Field(pattern=r"^[A-Z]{2}$")
    alert_languages:list[str]=Field(default_factory=lambda:["en"],max_length=10)

@router.get("/preferences")
async def get_prefs(principal:Principal=Depends(get_principal))->dict:
    async def _do():
        client=await supabase._ensure()
        return await client.table("tenant_preferences").select("*").eq("tenant_id",str(principal.tenant_id)).limit(1).execute()
    resp=await supabase._retry(_do); rows=resp.data or []
    return rows[0] if rows else {"default_locale":"en","default_region":"US","timezone":"UTC","country":"US","alert_languages":["en"]}

@router.put("/preferences")
async def set_prefs(body:PrefsUpdate,principal:Principal=Depends(require_role("owner","admin")))->dict:
    async def _do():
        client=await supabase._ensure()
        return await client.table("tenant_preferences").upsert({
            "tenant_id":str(principal.tenant_id),**body.model_dump(),
            "updated_at":datetime.now(timezone.utc).isoformat(),
        },on_conflict="tenant_id").execute()
    resp=await supabase._retry(_do); return (resp.data or [{}])[0]

class ChannelSub(BaseModel):
    channel_ids:list[str]=Field(min_length=0,max_length=200)

@router.post("/channels/subscribe")
async def subscribe_channels(body:ChannelSub,principal:Principal=Depends(require_role("owner","admin")))->dict:
    client=await supabase._ensure()
    requested=set(body.channel_ids)
    if requested:
        check=await client.table("lens_channel_catalog").select("id").in_("id",list(requested)).execute()
        valid={r["id"] for r in (check.data or [])}
        missing=requested-valid
        if missing: raise HTTPException(status_code=400,detail={"unknown_channel_ids":sorted(missing)})
    async def _do():
        if requested:
            await client.table("lens_channel_subscriptions").upsert(
                [{"tenant_id":str(principal.tenant_id),"channel_id":cid,"enabled":True} for cid in requested],
                on_conflict="tenant_id,channel_id").execute()
        return await client.table("lens_channel_subscriptions").select("channel_id").eq("tenant_id",str(principal.tenant_id)).execute()
    resp=await supabase._retry(_do); return {"subscribed":len(resp.data or [])}

@router.get("/channels/subscriptions")
async def list_channel_subs(principal:Principal=Depends(get_principal))->list[dict]:
    async def _do():
        client=await supabase._ensure()
        return await client.table("lens_channel_subscriptions").select("channel_id,enabled,subscribed_at").eq("tenant_id",str(principal.tenant_id)).execute()
    resp=await supabase._retry(_do); return list(resp.data or [])
