from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
import os
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router=APIRouter(tags=["customer-identity"])

def principal(p: DeveloperPrincipal=Depends(authenticate_request))->DeveloperPrincipal:
    p.require(("console:read",)); return p

def operator_principal(p: DeveloperPrincipal=Depends(authenticate_request))->DeveloperPrincipal:
    p.require(("console:read",))
    allowed={x.strip() for x in os.getenv("CYCLOTHONE_OPERATOR_USER_IDS","").split(",") if x.strip()}
    if not p.user_id or p.user_id not in allowed:
        raise HTTPException(403,detail="operator_administrator_required")
    return p


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

class AdmissionDecisionRequest(BaseModel):
    reason: str|None=None


@router.get("/customer/admissions")
async def admissions(p: DeveloperPrincipal=Depends(operator_principal)):
    rows=await supabase.select(
        "organization_admissions",
        "id,organization_id,requested_by,status,assurance_level,reviewer_user_id,decision_reason,submitted_at,reviewed_at,created_at,updated_at",
        status="pending",
    )
    enriched=[]
    for admission in rows:
        organization=await supabase.select_one(
            "customer_organizations",
            "id,owner_user_id,tenant_id,organization_type,legal_name,country_code,website_domain,registration_number,verification_status,admission_status,created_at,updated_at",
            id=admission["organization_id"],
        )
        verifications=await supabase.select(
            "identity_verifications",
            "id,verification_type,status,provider,reference,submitted_at,verified_at,expires_at,created_at",
            organization_id=admission["organization_id"],
        )
        service_requests=await supabase.select(
            "service_requests",
            "id,service_key,urgency,description,status,requester_user_id,created_at,updated_at",
            organization_id=admission["organization_id"],
        )
        enriched.append({
            **admission,
            "organization": organization,
            "verifications": verifications,
            "service_requests": service_requests,
        })
    return {"admissions":enriched}


@router.post("/customer/admissions/{admission_id}/approve")
async def approve_admission(admission_id: str, body: AdmissionDecisionRequest, p: DeveloperPrincipal=Depends(operator_principal)):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    try:
        tenant_id=await supabase.rpc("approve_customer_workspace",{"p_admission_id":admission_id,"p_reviewer":p.user_id,"p_reason":body.reason})
    except Exception as exc:
        detail=str(exc)
        if "verification_required" in detail: raise HTTPException(409,detail="verification_required")
        if "not_actionable" in detail: raise HTTPException(409,detail="admission_not_actionable")
        raise
    return {"status":"approved","tenant_id":tenant_id}


@router.post("/customer/admissions/{admission_id}/reject")
async def reject_admission(admission_id: str, body: AdmissionDecisionRequest, p: DeveloperPrincipal=Depends(operator_principal)):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    if not body.reason or len(body.reason.strip())<3:
        raise HTTPException(422,detail="rejection_reason_required")
    try:
        org_id=await supabase.rpc("reject_customer_workspace",{"p_admission_id":admission_id,"p_reviewer":p.user_id,"p_reason":body.reason.strip()})
    except Exception as exc:
        if "not_actionable" in str(exc): raise HTTPException(409,detail="admission_not_actionable")
        raise
    return {"status":"rejected","organization_id":org_id}


@router.post("/customer/organizations/{organization_id}/admission")
async def request_admission(organization_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    try:
        admission_id=await supabase.rpc("request_workspace_admission",{"p_organization_id":organization_id})
    except Exception as exc:
        detail=str(exc)
        if "organization_not_found" in detail: raise HTTPException(404,detail="organization_not_found")
        if "already_actionable" in detail: raise HTTPException(409,detail="admission_already_actionable")
        raise
    return {"admission_id":admission_id,"status":"pending"}

@router.get("/customer/organizations")
async def organizations(p:DeveloperPrincipal=Depends(principal)):
    rows=await supabase.select("customer_organizations","id,tenant_id,organization_type,legal_name,country_code,website_domain,registration_number,verification_status,created_at,updated_at",owner_user_id=p.user_id)
    return {"organizations":rows}

@router.post("/customer/organizations")
async def create_organization(body:OrgRequest,p:DeveloperPrincipal=Depends(principal)):
    if body.organization_type not in {"company","government","security_provider","developer","client","partner","individual"}: raise HTTPException(400,detail="invalid organization type")
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    row=await supabase.insert_one("customer_organizations",{"owner_user_id":p.user_id,"tenant_id":p.tenant_id,"organization_type":body.organization_type,"legal_name":body.legal_name.strip(),"country_code":body.country_code,"website_domain":body.website_domain,"registration_number":body.registration_number,"verification_status":"pending"})
    return row


class VerificationRequest(BaseModel):
    verification_type: str
    provider: str|None=None
    reference: str|None=None

@router.get("/customer/organizations/{organization_id}/verification")
async def verification_status(organization_id: str, p:DeveloperPrincipal=Depends(principal)):
    org=await supabase.select_one("customer_organizations","id,verification_status",id=organization_id,owner_user_id=p.user_id)
    if not org: raise HTTPException(404,detail="organization_not_found")
    rows=await supabase.select("identity_verifications","id,verification_type,status,provider,reference,submitted_at,verified_at,expires_at,created_at",organization_id=organization_id)
    return {"organization":org,"verifications":rows}

@router.post("/customer/organizations/{organization_id}/verification")
async def submit_verification(organization_id: str, body: VerificationRequest, p:DeveloperPrincipal=Depends(principal)):
    allowed={"email","domain","identity","business","government","authorization"}
    if body.verification_type not in allowed: raise HTTPException(400,detail="invalid_verification_type")
    org=await supabase.select_one("customer_organizations","id,verification_status",id=organization_id,tenant_id=p.tenant_id,owner_user_id=p.user_id)
    if not org: raise HTTPException(404,detail="organization_not_found")
    row=await supabase.insert_one("identity_verifications",{"organization_id":organization_id,"subject_user_id":p.user_id,"verification_type":body.verification_type,"status":"submitted","provider":body.provider,"reference":body.reference})
    return row

@router.get("/customer/service-requests")
async def service_requests(p:DeveloperPrincipal=Depends(principal)):
    orgs=await supabase.select("customer_organizations","id",owner_user_id=p.user_id,tenant_id=p.tenant_id)
    org_ids=[r["id"] for r in orgs]
    rows=[]
    for org_id in org_ids:
        rows.extend(await supabase.select("service_requests","id,organization_id,requester_user_id,service_key,urgency,description,status,created_at,updated_at",organization_id=org_id,requester_user_id=p.user_id))
    return {"service_requests":rows}

@router.post("/customer/service-requests")
async def create_service_request(body:ServiceRequest,p:DeveloperPrincipal=Depends(principal)):
    org=await supabase.select_one("customer_organizations","id,tenant_id,admission_status",id=body.organization_id,owner_user_id=p.user_id)
    if not org or org.get("admission_status") != "approved": raise HTTPException(403,detail="workspace_not_admitted")
    if not org: raise HTTPException(404,detail="organization_not_found")
    if body.service_key not in {"cybersecurity_assessment","incident_response","threat_intelligence","brand_protection","dark_web_monitoring","soc_mdr","ai_security","physical_security","compliance","other"}: raise HTTPException(400,detail="invalid service")
    if body.urgency not in {"low","normal","high","critical"}: raise HTTPException(400,detail="invalid urgency")
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    row=await supabase.insert_one("service_requests",{"organization_id":body.organization_id,"requester_user_id":p.user_id,"service_key":body.service_key,"urgency":body.urgency,"description":body.description.strip(),"status":"submitted"})
    return row
