from __future__ import annotations
from datetime import UTC, datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from cyclothone.api.routes.customer_identity import operator_principal, principal as customer_principal
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.mobile_intelligence.service import MobileIntelligenceError, MobileIntelligenceService, CAPABILITIES, normalize_number, subject_hash
from cyclothone.storage.supabase_client import supabase

router=APIRouter(prefix="/mobile-intelligence",tags=["mobile-intelligence"]); service=MobileIntelligenceService()
def principal(p:DeveloperPrincipal=Depends(authenticate_request))->DeveloperPrincipal: p.require(("mobile:intelligence",)); return p
class AuthorizationRequest(BaseModel):
    purpose:str=Field(min_length=3,max_length=120); authority_reference:str=Field(min_length=3,max_length=240); number:str=Field(min_length=7,max_length=20); valid_hours:int=Field(default=24,ge=1,le=720)
class IntelligenceRequest(BaseModel):
    number:str=Field(min_length=7,max_length=20); capabilities:list[str]=Field(min_length=1,max_length=20); purpose:str=Field(min_length=3,max_length=120); authority_reference:str=Field(min_length=3,max_length=240); authorization_id:str; max_age_hours:int=Field(default=24,ge=1,le=720); latitude:float|None=Field(default=None,ge=-90,le=90); longitude:float|None=Field(default=None,ge=-180,le=180); radius_km:int|None=Field(default=None,ge=1,le=100)

@router.get("/customer-status")
async def customer_status(p:DeveloperPrincipal=Depends(customer_principal)):
    if not p.tenant_id: raise HTTPException(403,"workspace_not_admitted")
    return await service.status(__import__("uuid").UUID(p.tenant_id))

@router.get("/capabilities")
async def capabilities(p:DeveloperPrincipal=Depends(principal)): return {"service":"mobile_digital_intelligence","capabilities":sorted(CAPABILITIES)}
@router.get("/status")
async def status(p:DeveloperPrincipal=Depends(principal)): return await service.status(__import__("uuid").UUID(p.tenant_id))
@router.post("/authorizations",status_code=201)
async def create_authorization(body:AuthorizationRequest,p:DeveloperPrincipal=Depends(principal)):
    try: normalized=normalize_number(body.number)
    except MobileIntelligenceError as exc: raise HTTPException(422,str(exc)) from exc
    row=await supabase.insert_one("mobile_authorizations",{"tenant_id":p.tenant_id,"app_id":p.app_id,"subject_hash":subject_hash(normalized),"purpose":body.purpose.strip(),"authority_reference":body.authority_reference.strip(),"valid_from":datetime.now(UTC).isoformat(),"valid_to":(datetime.now(UTC)+timedelta(hours=body.valid_hours)).isoformat(),"status":"pending","requested_by":p.user_id})
    return {"id":str(row["id"]),"status":"pending"}
@router.post("/authorizations/{authorization_id}/approve")
async def approve_authorization(authorization_id:str,p:DeveloperPrincipal=Depends(operator_principal)):
    row=await supabase.select_one("mobile_authorizations","id,tenant_id,status,valid_to",id=authorization_id,tenant_id=p.tenant_id)
    if not row: raise HTTPException(404,"authorization_not_found")
    if row.get("status")!="pending": raise HTTPException(409,"authorization_not_pending")
    updated=await supabase.update("mobile_authorizations",{"status":"approved","approved_by":p.user_id},id=authorization_id,tenant_id=p.tenant_id)
    return {"id":authorization_id,"status":"approved","tenant_id":updated.get("tenant_id") if updated else row.get("tenant_id")}
@router.post("/authorizations/{authorization_id}/revoke")
async def revoke_authorization(authorization_id:str,p:DeveloperPrincipal=Depends(operator_principal)):
    row=await supabase.select_one("mobile_authorizations","id,status",id=authorization_id,tenant_id=p.tenant_id)
    if not row: raise HTTPException(404,"authorization_not_found")
    updated=await supabase.update("mobile_authorizations",{"status":"revoked"},id=authorization_id,tenant_id=p.tenant_id); return {"id":authorization_id,"status":updated.get("status") if updated else "revoked"}
@router.post("/query")
async def query(body:IntelligenceRequest,p:DeveloperPrincipal=Depends(principal)):
    try:
        return await service.query(__import__("uuid").UUID(p.tenant_id),p.app_id,body.number,body.capabilities,body.purpose,body.authority_reference,body.authorization_id,body.max_age_hours,body.latitude,body.longitude,body.radius_km)
    except MobileIntelligenceError as exc:
        detail=str(exc); status=403 if "authorization" in detail or "context" in detail else 422
        if detail.startswith("provider_") or detail.startswith("no_enabled_mobile_provider"): status=503
        raise HTTPException(status,detail) from exc
@router.get("/queries/{query_id}")
async def query_detail(query_id:str,p:DeveloperPrincipal=Depends(principal)):
    row=await supabase.select_one("mobile_queries","id,status,capabilities,subject_hash,requested_at,completed_at,error_code",id=query_id,tenant_id=p.tenant_id,app_id=p.app_id)
    if not row: raise HTTPException(404,"query_not_found")
    observations=await supabase.select("mobile_observations","id,provider_id,capability,data,observed_at",query_id=query_id); return {"query":row,"observations":observations}
