from __future__ import annotations
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from cyclothone.api.deps import get_principal, require_role
from cyclothone.security.jwt import Principal
from cyclothone.storage.supabase_client import supabase
from cyclothone.banking.fapi.policy import FapiPolicy, FapiRequest, hash_state, validate_https_uri

router=APIRouter()

class ClientRegistration(BaseModel):
    client_id: str=Field(min_length=3,max_length=200)
    client_name: str=Field(min_length=1,max_length=200)
    redirect_uris: list[str]=Field(min_length=1,max_length=20)
    scopes: list[str]=Field(default_factory=lambda:["openid"],max_length=50)
    token_endpoint_auth_method: str=Field(default="tls_client_auth",pattern="^(tls_client_auth|self_signed_tls_client_auth|private_key_jwt)$")
    require_dpop: bool=False
    jwks_uri: str|None=None
    mtls_subject: str|None=None

@router.post("/fapi/clients")
async def register_client(body:ClientRegistration, principal:Principal=Depends(require_role("owner","admin"))):
    if any(not validate_https_uri(u) for u in body.redirect_uris):
        raise HTTPException(400,"all redirect_uris must use HTTPS")
    if body.token_endpoint_auth_method=="private_key_jwt" and not body.jwks_uri:
        raise HTTPException(400,"jwks_uri required for private_key_jwt")
    payload={**body.model_dump(),"tenant_id":str(principal.tenant_id)}
    async def _do():
        c=await supabase._ensure()
        return await c.table("fapi_clients").insert(payload).execute()
    try: resp=await supabase._retry(_do)
    except Exception as e: raise HTTPException(409,"client_id already registered or invalid") from e
    return resp.data[0]

@router.get("/fapi/clients")
async def list_clients(principal:Principal=Depends(get_principal)):
    async def _do():
        c=await supabase._ensure()
        return await c.table("fapi_clients").select("*").eq("tenant_id",str(principal.tenant_id)).execute()
    return (await supabase._retry(_do)).data or []

class AuthorizationCheck(BaseModel):
    client_id:str
    redirect_uri:str
    response_type:str="code"
    scope:str="openid"
    state:str|None=None
    code_challenge:str|None=None
    code_challenge_method:str|None=None

@router.post("/fapi/authorize/check")
async def authorize_check(body:AuthorizationCheck,principal:Principal=Depends(get_principal)):
    async def _do():
        c=await supabase._ensure()
        return await c.table("fapi_clients").select("*").eq("tenant_id",str(principal.tenant_id)).eq("client_id",body.client_id).maybe_single().execute()
    row=(await supabase._retry(_do)).data
    if not row: raise HTTPException(404,"client not found")
    verdict=FapiPolicy(row).validate(FapiRequest(client_id=body.client_id,redirect_uri=body.redirect_uri,response_type=body.response_type,code_challenge=body.code_challenge,code_challenge_method=body.code_challenge_method,scope=body.scope))
    if not verdict.allowed: raise HTTPException(400,{"code":"fapi_request_denied","reasons":verdict.reasons})
    return {"allowed":True,"state_hash":hash_state(body.state) if body.state else None}

class ReplayProof(BaseModel):
    client_id:str
    jti:str=Field(min_length=16,max_length=256)
    iat:int
    htm:str
    htu:str

@router.post("/fapi/dpop/check")
async def dpop_check(body:ReplayProof,principal:Principal=Depends(get_principal)):
    if not validate_https_uri(body.htu): raise HTTPException(400,"htu must be HTTPS")
    now=int(datetime.now(timezone.utc).timestamp())
    if abs(now-body.iat)>FapiPolicy.MAX_DPOP_AGE: raise HTTPException(400,"proof expired")
    async def _do():
        c=await supabase._ensure()
        return await c.rpc("fapi_claim_replay",{"p_tenant":str(principal.tenant_id),"p_jti":body.jti,"p_client_id":body.client_id,"p_expires":(datetime.now(timezone.utc)+timedelta(seconds=FapiPolicy.MAX_DPOP_AGE)).isoformat()}).execute()
    try: resp=await supabase._retry(_do,attempts=1)
    except Exception as e: raise HTTPException(503,"replay protection unavailable") from e
    if resp.data is not True: raise HTTPException(400,"replayed proof")
    return {"allowed":True,"jti":body.jti}

@router.get("/fapi/consents")
async def list_consents(principal:Principal=Depends(get_principal),limit:int=Query(100,ge=1,le=500)):
    async def _do():
        c=await supabase._ensure()
        return await c.table("fapi_consents").select("*").eq("tenant_id",str(principal.tenant_id)).order("created_at",desc=True).limit(limit).execute()
    return (await supabase._retry(_do)).data or []
