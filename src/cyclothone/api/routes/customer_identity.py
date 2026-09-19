from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router=APIRouter(tags=["customer-identity"])

def principal(p: DeveloperPrincipal=Depends(authenticate_request))->DeveloperPrincipal:
    p.require(("console:read",)); return p

class OrgRequest(BaseModel):
    organization_type: str
    legal_name: str=Field(min_length=1,max_length=240)
    country_code: str|None=None
    website_domain: str|None=None
    registration_number: str|None=None

class ServiceRequest(BaseModel):
    organization_id: str
    service_key: str
    urgency: str="normal"
    description: str=Field(min_length=10,max_length=10000)

@router.get("/customer/organizations")
async def organizations(p:DeveloperPrincipal=Depends(principal)):
    rows=await supabase.select("customer_organizations","id,tenant_id,organization_type,legal_name,country_code,website_domain,registration_number,verification_status,created_at,updated_at",tenant_id=p.tenant_id)
    return {"organizations":rows}

@router.post("/customer/organizations")
async def create_organization(body:OrgRequest,p:DeveloperPrincipal=Depends(principal)):
    if body.organization_type not in {"company","government","security_provider","developer","client","partner","individual"}: raise HTTPException(400,detail="invalid organization type")
    row=await supabase.insert("customer_organizations",{"owner_user_id":p.app_id,"tenant_id":p.tenant_id,"organization_type":body.organization_type,"legal_name":body.legal_name.strip(),"country_code":body.country_code,"website_domain":body.website_domain,"registration_number":body.registration_number,"verification_status":"pending"})
    return row

@router.get("/customer/service-requests")
async def service_requests(p:DeveloperPrincipal=Depends(principal)):
    rows=await supabase.select("service_requests","id,organization_id,requester_user_id,service_key,urgency,description,status,created_at,updated_at",organization_id=p.tenant_id)
    return {"service_requests":rows}

@router.post("/customer/service-requests")
async def create_service_request(body:ServiceRequest,p:DeveloperPrincipal=Depends(principal)):
    org=await supabase.select_one("customer_organizations","id,tenant_id",id=body.organization_id,tenant_id=p.tenant_id)
    if not org: raise HTTPException(404,detail="organization_not_found")
    if body.service_key not in {"cybersecurity_assessment","incident_response","threat_intelligence","brand_protection","dark_web_monitoring","soc_mdr","ai_security","physical_security","compliance","other"}: raise HTTPException(400,detail="invalid service")
    if body.urgency not in {"low","normal","high","critical"}: raise HTTPException(400,detail="invalid urgency")
    row=await supabase.insert("service_requests",{"organization_id":body.organization_id,"requester_user_id":p.app_id,"service_key":body.service_key,"urgency":body.urgency,"description":body.description.strip(),"status":"submitted"})
    return row
