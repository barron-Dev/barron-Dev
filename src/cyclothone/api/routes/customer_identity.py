from __future__ import annotations
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from datetime import UTC, datetime, timedelta
import hashlib
import secrets
import os
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router=APIRouter(tags=["customer-identity"])

async def principal(authorization: str | None = Header(None)) -> DeveloperPrincipal:
    """Authenticate developer credentials or a Supabase customer session."""
    if not authorization:
        raise HTTPException(401, detail="authentication_required", headers={"WWW-Authenticate": "Bearer"})
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, detail="invalid_bearer_token", headers={"WWW-Authenticate": "Bearer"})
    raw = token.strip()
    try:
        developer = await authenticate_request(authorization=authorization, x_api_key=None)
        developer.require(("console:read",))
        return developer
    except HTTPException as exc:
        if exc.status_code not in {401, 403}: raise
    try:
        auth_result = await (await supabase._ensure()).auth.get_user(raw)
        user = getattr(auth_result, "user", None)
        user_id = str(getattr(user, "id", "") or "")
    except Exception as exc:
        raise HTTPException(401, detail="invalid_customer_session", headers={"WWW-Authenticate": "Bearer"}) from exc
    if not user_id:
        raise HTTPException(401, detail="invalid_customer_session", headers={"WWW-Authenticate": "Bearer"})
    orgs = await supabase.select("customer_organizations", "id,tenant_id", owner_user_id=user_id)
    if not orgs:
        memberships = await supabase.select("organization_members", "organization_id", user_id=user_id, status="active")
        orgs = []
        for membership in memberships:
            org = await supabase.select_one("customer_organizations", "id,tenant_id", id=str(membership["organization_id"]))
            if org: orgs.append(org)
    tenant_id = next((str(row["tenant_id"]) for row in orgs if row.get("tenant_id")), "")
    return DeveloperPrincipal(tenant_id, f"customer:{user_id}", user_id, frozenset({"console:read"}), "customer")

def operator_principal(p: DeveloperPrincipal=Depends(authenticate_request))->DeveloperPrincipal:
    p.require(("console:read",))
    allowed={x.strip() for x in os.getenv("CYCLOTHONE_OPERATOR_USER_IDS","").split(",") if x.strip()}
    if not p.user_id or p.user_id not in allowed:
        raise HTTPException(403,detail="operator_administrator_required")
    return p


class OrgRequest(BaseModel):
    organization_type: str = "company"
    legal_name: str=Field(min_length=1,max_length=240)
    country_code: str|None=None
    website_domain: str|None=None
    registration_number: str|None=None

class ServiceRequest(BaseModel):
    organization_id: str|None = None
    service_key: str
    urgency: str="normal"
    description: str=Field(min_length=10,max_length=10000)
    target: str|None = Field(default=None, min_length=2, max_length=2000)
    target_type: str|None = None

class AdmissionDecisionRequest(BaseModel):
    reason: str|None=None

class RecoveryPolicyRequest(BaseModel):
    retention_days: int = Field(default=30, ge=1, le=3650)
    rpo_minutes: int = Field(default=15, ge=1, le=1440)

class InvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=20,max_length=512)

@router.post("/customer/invitations/accept")
async def accept_invitation(body: InvitationAcceptRequest, p: DeveloperPrincipal=Depends(principal)):
    try:
        organization_id=await supabase.rpc("accept_organization_invitation",{"p_token":body.token.strip()})
    except Exception as exc:
        detail=str(exc)
        mapping={
            "authentication required":(401,"authentication_required"),
            "authenticated_email_required":(403,"authenticated_email_required"),
            "invalid_invitation_token":(400,"invalid_invitation_token"),
            "invitation_not_found":(404,"invitation_not_found"),
            "invitation_already_accepted":(409,"invitation_already_accepted"),
            "invitation_expired":(410,"invitation_expired"),
            "invitation_email_mismatch":(403,"invitation_email_mismatch"),
            "invalid_invitation_role":(400,"invalid_invitation_role"),
        }
        for key,(status,code) in mapping.items():
            if key in detail: raise HTTPException(status,detail=code)
        raise
    return {"status":"accepted","organization_id":organization_id}

class InvitationRequest(BaseModel):
    email: str = Field(min_length=3,max_length=320)
    role: str = "requester"



class OpenCaseRequest(BaseModel):
    category: str = "other"
    severity: str = "medium"

@router.get("/customer/cases")
async def customer_cases(p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    memberships=await supabase.select("organization_members","organization_id",user_id=p.user_id,status="active")
    org_ids=list({x["organization_id"] for x in memberships})
    items=[]
    for oid in org_ids:
        links=await supabase.select("customer_case_links","id,organization_id,service_request_id,case_id,created_at",organization_id=oid)
        for link in links:
            case=await supabase.select_one("crime_cases","id,case_number,category,severity,status,title,summary,created_at,updated_at",id=link["case_id"])
            req=await supabase.select_one("service_requests","id,service_key,urgency,status,created_at,updated_at",id=link["service_request_id"])
            if case: items.append({**link,"case":case,"service_request":req})
    return {"cases":items}

@router.get("/customer/cases/{case_id}")
async def customer_case_detail(case_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    link=await supabase.select_one("customer_case_links","id,organization_id,service_request_id,case_id,created_at",case_id=case_id)
    if not link: raise HTTPException(404,detail="case_not_found")
    member=await supabase.select_one("organization_members","organization_id,user_id,status,role",organization_id=link["organization_id"],user_id=p.user_id,status="active")
    if not member: raise HTTPException(404,detail="case_not_found")
    case=await supabase.select_one("crime_cases","id,tenant_id,case_number,category,severity,status,title,summary,evidence,device_id,created_at,updated_at",id=case_id)
    req=await supabase.select_one("service_requests","id,service_key,urgency,description,status,requester_user_id,created_at,updated_at",id=link["service_request_id"])
    assignment=await supabase.select_one("customer_case_assignments","id,operator_user_id,assigned_by,active,created_at,ended_at",case_id=case_id,active=True)
    return {"case":case,"service_request":req,"link":link,"assignment":assignment}

@router.post("/customer/cases/{case_id}/activity")
async def customer_case_update(case_id: str, body: dict, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    message=str(body.get("message") or "").strip()
    if not message: raise HTTPException(422,detail="message_required")
    try:
        activity_id=await supabase.rpc("add_customer_case_activity",{"p_case_id":case_id,"p_user_id":p.user_id,"p_message":message})
    except Exception as exc:
        detail=str(exc)
        if "case_not_found" in detail or "organization_access_required" in detail: raise HTTPException(404,detail="case_not_found")
        if "invalid_activity_message" in detail: raise HTTPException(422,detail="invalid_activity_message")
        raise
    return {"id":activity_id,"status":"recorded"}

@router.post("/customer/cases/{case_id}/transition")
async def transition_case(case_id: str, body: dict, p: DeveloperPrincipal=Depends(operator_principal)):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    status=str(body.get("status") or "")
    reason=str(body.get("reason") or "").strip() or None
    try:
        new_status=await supabase.rpc("transition_customer_case",{"p_case_id":case_id,"p_operator_user_id":p.user_id,"p_status":status,"p_reason":reason})
    except Exception as exc:
        detail=str(exc)
        if "case_not_found" in detail or "customer_case_not_found" in detail: raise HTTPException(404,detail="case_not_found")
        if "invalid_case_status" in detail: raise HTTPException(422,detail="invalid_case_status")
        raise
    return {"case_id":case_id,"status":new_status}

@router.get("/customer/cases/{case_id}/actions")
async def customer_case_actions(case_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    link=await supabase.select_one("customer_case_links","organization_id",case_id=case_id)
    if not link: raise HTTPException(404,detail="case_not_found")
    member=await supabase.select_one("organization_members","organization_id,user_id,status",organization_id=link["organization_id"],user_id=p.user_id,status="active")
    if not member: raise HTTPException(404,detail="case_not_found")
    actions=await supabase.select("case_actions","id,case_id,action,args,status,created_at,updated_at,approved_at,dispatched_at,error",case_id=case_id)
    return {"actions":actions}

@router.get("/customer/cases/{case_id}/activity")
async def customer_case_activity(case_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    link=await supabase.select_one("customer_case_links","case_id,organization_id",case_id=case_id)
    if not link: raise HTTPException(404,detail="case_not_found")
    member=await supabase.select_one("organization_members","organization_id,user_id,status",organization_id=link["organization_id"],user_id=p.user_id,status="active")
    if not member: raise HTTPException(404,detail="case_not_found")
    rows=await supabase.select("customer_case_activity","id,case_id,actor_user_id,actor_type,event_type,message,metadata,created_at",case_id=case_id)
    return {"activity":rows}

@router.post("/customer/admissions/service-requests/{service_request_id}/open-case")
async def open_case(service_request_id: str, body: OpenCaseRequest, p: DeveloperPrincipal=Depends(operator_principal)):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    try:
        case_id=await supabase.rpc("open_customer_case",{"p_service_request_id":service_request_id,"p_operator_user_id":p.user_id,"p_category":body.category,"p_severity":body.severity})
    except Exception as exc:
        detail=str(exc)
        mapping={"service_request_not_found":404,"workspace_not_admitted":403,"invalid_case_category":422,"invalid_case_severity":422}
        for key,status in mapping.items():
            if key in detail: raise HTTPException(status,detail=key)
        raise
    return {"status":"opened","case_id":case_id}

@router.get("/customer/operator/cases")
async def operator_cases(p: DeveloperPrincipal=Depends(operator_principal)):
    rows=await supabase.select("crime_cases","id,tenant_id,case_number,category,severity,status,title,summary,device_id,created_at,updated_at",tenant_id=p.tenant_id)
    result=[]
    for case in rows:
        link=await supabase.select_one("customer_case_links","organization_id,service_request_id,case_id,created_at",case_id=case["id"])
        if not link: continue
        req=await supabase.select_one("service_requests","id,service_key,urgency,status,requester_user_id,created_at,updated_at",id=link["service_request_id"])
        assignment=await supabase.select_one("customer_case_assignments","operator_user_id,assigned_by,active,created_at,ended_at",case_id=case["id"],active=True)
        result.append({"case":case,"link":link,"service_request":req,"assignment":assignment})
    return {"cases":result}

@router.post("/customer/operator/cases/{case_id}/assign")
async def assign_case(case_id: str, body: dict, p: DeveloperPrincipal=Depends(operator_principal)):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    operator_user_id=str(body.get("operator_user_id") or "").strip()
    if not operator_user_id: raise HTTPException(422,detail="operator_user_id_required")
    try:
        assignment_id=await supabase.rpc("assign_customer_case",{"p_case_id":case_id,"p_operator_user_id":p.user_id,"p_assigned_operator":operator_user_id})
    except Exception as exc:
        detail=str(exc)
        if "case_not_found" in detail: raise HTTPException(404,detail="case_not_found")
        if "assigned_operator_not_found" in detail: raise HTTPException(404,detail="assigned_operator_not_found")
        raise
    return {"assignment_id":assignment_id,"case_id":case_id,"operator_user_id":operator_user_id}

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
        if "admission_already_pending" in detail: raise HTTPException(409,detail="admission_already_pending")
        raise
    return {"admission_id":admission_id,"status":"pending"}

@router.get("/customer/organizations/{organization_id}/members")
async def organization_members(organization_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    org=await supabase.select_one("customer_organizations","id,owner_user_id",id=organization_id,owner_user_id=p.user_id)
    if not org:
        member=await supabase.select_one("organization_members","organization_id,user_id,role,status,created_at",organization_id=organization_id,user_id=p.user_id,status="active")
        if not member: raise HTTPException(404,detail="organization_not_found")
    rows=await supabase.select("organization_members","organization_id,user_id,role,status,created_at",organization_id=organization_id)
    return {"members":rows}

@router.post("/customer/organizations/{organization_id}/invitations/{invitation_id}/revoke")
async def revoke_invitation(organization_id: str, invitation_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    org=await supabase.select_one("customer_organizations","id,owner_user_id",id=organization_id,owner_user_id=p.user_id)
    if not org:
        member=await supabase.select_one("organization_members","organization_id,user_id,role,status",organization_id=organization_id,user_id=p.user_id,status="active")
        if not member or member["role"] not in {"owner","admin"}: raise HTTPException(403,detail="organization_admin_required")
    invitation=await supabase.select_one("organization_invitations","id,organization_id,accepted_at",id=invitation_id,organization_id=organization_id)
    if not invitation: raise HTTPException(404,detail="invitation_not_found")
    if invitation.get("accepted_at"): raise HTTPException(409,detail="invitation_already_closed")
    await supabase.update("organization_invitations",{"expires_at":datetime.now(UTC).isoformat(),"accepted_at":datetime.now(UTC).isoformat()},id=invitation_id,organization_id=organization_id)
    return {"status":"revoked","invitation_id":invitation_id}

@router.get("/customer/organizations/{organization_id}/invitations")
async def organization_invitations(organization_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    org=await supabase.select_one("customer_organizations","id,owner_user_id",id=organization_id,owner_user_id=p.user_id)
    if not org:
        member=await supabase.select_one("organization_members","organization_id,user_id,role,status",organization_id=organization_id,user_id=p.user_id,status="active")
        if not member or member["role"] not in {"owner","admin"}: raise HTTPException(403,detail="organization_admin_required")
    rows=await supabase.select("organization_invitations","id,organization_id,invited_by,email,role,expires_at,accepted_at,accepted_user_id,created_at",organization_id=organization_id)
    return {"invitations":rows}

@router.post("/customer/organizations/{organization_id}/invitations")
async def create_invitation(organization_id: str, body: InvitationRequest, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id: raise HTTPException(403,detail="user_identity_required")
    if body.role not in {"admin","security_admin","analyst","developer","requester","viewer"}: raise HTTPException(400,detail="invalid_invitation_role")
    org=await supabase.select_one("customer_organizations","id,owner_user_id,admission_status,tenant_id",id=organization_id,owner_user_id=p.user_id)
    if not org:
        member=await supabase.select_one("organization_members","organization_id,user_id,role,status",organization_id=organization_id,user_id=p.user_id,status="active")
        if not member or member["role"] not in {"owner","admin"}: raise HTTPException(403,detail="organization_admin_required")
        org={"id":organization_id,"admission_status":"approved","tenant_id":True}
    if org.get("admission_status") != "approved" or not org.get("tenant_id"): raise HTTPException(403,detail="workspace_not_admitted")
    email=body.email.strip().lower()
    existing=await supabase.select_one("organization_invitations","id,accepted_at,expires_at",organization_id=organization_id,email=email)
    if existing and not existing.get("accepted_at"):
        try:
            if datetime.fromisoformat(str(existing["expires_at"]).replace("Z","+00:00")) > datetime.now(UTC):
                raise HTTPException(409,detail="active_invitation_exists")
        except ValueError:
            pass
    raw=secrets.token_urlsafe(32)
    token_hash=hashlib.sha256(raw.encode()).hexdigest()
    expires=(datetime.now(UTC)+timedelta(hours=72)).isoformat()
    row=await supabase.insert_one("organization_invitations",{"organization_id":organization_id,"invited_by":p.user_id,"email":email,"role":body.role,"token_hash":token_hash,"expires_at":expires})
    return {"invitation":row,"invite_token":raw,"warning":"Deliver this one-time token through a trusted invitation channel; it is not stored in plaintext."}

@router.get("/customer/organizations")
async def organizations(p:DeveloperPrincipal=Depends(principal)):
    rows=await supabase.select("customer_organizations","id,tenant_id,organization_type,legal_name,country_code,website_domain,registration_number,verification_status,admission_status,created_at,updated_at",owner_user_id=p.user_id)
    return {"organizations":rows}

@router.post("/customer/organizations")
async def create_organization(body:OrgRequest,p:DeveloperPrincipal=Depends(principal)):
    if body.organization_type not in {"company","government","security_provider","developer","client","partner","individual"}:
        raise HTTPException(400,detail="invalid_organization_type")
    if not p.user_id:
        raise HTTPException(403,detail="user_identity_required")
    try:
        organization_id=await supabase.rpc(
            "create_customer_organization_for_user",
            {
                "p_owner_user_id":p.user_id,
                "p_type":body.organization_type,
                "p_legal_name":body.legal_name.strip(),
                "p_country_code":body.country_code,
                "p_domain":body.website_domain,
                "p_registration_number":body.registration_number,
            },
        )
    except Exception as exc:
        detail=str(exc)
        if "authentication required" in detail:
            raise HTTPException(401,detail="authentication_required")
        if "user_identity_required" in detail:
            raise HTTPException(403,detail="user_identity_required")
        if "invalid organization type" in detail:
            raise HTTPException(400,detail="invalid_organization_type")
        raise
    row=await supabase.select_one(
        "customer_organizations",
        "id,tenant_id,organization_type,legal_name,country_code,website_domain,registration_number,verification_status,admission_status,created_at,updated_at",
        id=str(organization_id), owner_user_id=p.user_id,
    )
    if not row:
        raise HTTPException(500,detail="organization_creation_not_confirmed")
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
    org=await supabase.select_one(
        "customer_organizations",
        "id,tenant_id,verification_status,admission_status",
        id=organization_id,
        owner_user_id=p.user_id,
    )
    if not org: raise HTTPException(404,detail="organization_not_found")
    if org.get("admission_status") == "approved":
        raise HTTPException(409,detail="workspace_already_admitted")
    row=await supabase.insert_one(
        "identity_verifications",
        {
            "organization_id":organization_id,
            "subject_user_id":p.user_id,
            "verification_type":body.verification_type,
            "status":"submitted",
            "provider":body.provider,
            "reference":body.reference,
            "submitted_at":datetime.now(UTC).isoformat(),
        },
    )
    return row

@router.post("/customer/tenants/{tenant_id}/recovery-policy")
async def provision_recovery_policy(
    tenant_id: str,
    body: RecoveryPolicyRequest,
    p: DeveloperPrincipal=Depends(operator_principal),
):
    region=os.getenv("CYCLOTHONE_RECOVERY_REGION","").strip()
    bucket=os.getenv("CYCLOTHONE_RECOVERY_BUCKET","").strip()
    kms_ref=os.getenv("CYCLOTHONE_RECOVERY_KMS_KEY_REF","").strip() or None
    if not region or not bucket:
        raise HTTPException(503,detail="recovery_storage_configuration_missing")
    prefix=f"{tenant_id}/"
    try:
        policy_id=await supabase.rpc(
            "provision_recovery_policy",
            {
                "p_tenant_id":tenant_id,
                "p_reviewer":p.user_id,
                "p_region":region,
                "p_bucket":bucket,
                "p_prefix":prefix,
                "p_retention_days":body.retention_days,
                "p_rpo_minutes":body.rpo_minutes,
                "p_object_lock_mode":"NONE",
                "p_kms_key_ref":kms_ref,
            },
        )
    except Exception as exc:
        detail=str(exc)
        mapping={
            "tenant_not_found":(404,"tenant_not_found"),
            "recovery_storage_required":(422,"recovery_storage_required"),
            "invalid_recovery_policy":(422,"invalid_recovery_policy"),
            "reviewer_identity_mismatch":(403,"reviewer_identity_mismatch"),
        }
        for key,(code,msg) in mapping.items():
            if key in detail: raise HTTPException(code,detail=msg)
        raise
    return {"status":"enabled","policy_id":policy_id,"tenant_id":tenant_id,"object_lock_mode":"NONE"}


@router.post("/customer/admissions/verifications/{verification_id}/review")
async def review_verification(
    verification_id: str,
    body: AdmissionDecisionRequest,
    status: str,
    p: DeveloperPrincipal=Depends(operator_principal),
):
    if not p.user_id: raise HTTPException(403,detail="operator_identity_required")
    review_status=status.strip().lower()
    if review_status not in {"verified","rejected"}:
        raise HTTPException(422,detail="invalid_verification_review_status")
    try:
        organization_id=await supabase.rpc(
            "review_customer_verification",
            {
                "p_verification_id":verification_id,
                "p_reviewer":p.user_id,
                "p_status":review_status,
                "p_reason":body.reason,
            },
        )
    except Exception as exc:
        detail=str(exc)
        mapping={
            "verification_not_found":(404,"verification_not_found"),
            "organization_not_found":(404,"organization_not_found"),
            "verification_not_actionable":(409,"verification_not_actionable"),
            "unsupported_admission_verification_type":(422,"unsupported_admission_verification_type"),
            "reviewer_identity_mismatch":(403,"reviewer_identity_mismatch"),
            "invalid_verification_review_status":(422,"invalid_verification_review_status"),
        }
        for key,(code,msg) in mapping.items():
            if key in detail: raise HTTPException(code,detail=msg)
        raise
    return {"status":review_status,"organization_id":organization_id}


def _normalize_customer_target(raw: str, target_type: str) -> str:
    value = raw.strip()
    if not value or len(value) > 2000:
        raise HTTPException(422, detail="invalid_target")
    if target_type not in {"domain","url","email","brand","username","ip","other"}:
        raise HTTPException(422, detail="invalid_target_type")
    if target_type == "email":
        if value.count("@") != 1 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise HTTPException(422, detail="invalid_email_target")
        return value.lower()
    if target_type in {"domain","url"}:
        candidate = value if "://" in value else f"https://{value}"
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(422, detail="invalid_target")
        host = parsed.hostname.rstrip(".").lower()
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise HTTPException(422, detail="private_or_internal_target")
        except ValueError:
            if "." not in host or host in {"localhost","localhost.localdomain"} or host.endswith((".local",".internal",".localhost")):
                raise HTTPException(422, detail="private_or_internal_target")
        if target_type == "domain":
            if ":" in host:
                raise HTTPException(422, detail="invalid_domain")
            return host
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
    if target_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise HTTPException(422, detail="invalid_ip_target") from exc
        if not address.is_global:
            raise HTTPException(422, detail="private_or_internal_target")
        return str(address)
    if target_type in {"brand","username","other"}:
        return value.strip()
    raise HTTPException(422, detail="invalid_target_type")


async def _customer_request_access(request_id: str, user_id: str) -> tuple[dict, dict]:
    row = await supabase.select_one(
        "service_requests",
        "id,organization_id,requester_user_id,service_key,urgency,description,target,target_type,status,processing_state,attempts,started_at,completed_at,failure_code,result,created_at,updated_at",
        id=request_id,
    )
    if not row:
        raise HTTPException(404, detail="service_request_not_found")
    organization_id = str(row["organization_id"])
    member = await supabase.select_one(
        "organization_members", "organization_id,user_id,role,status",
        organization_id=organization_id, user_id=user_id, status="active",
    )
    org = await supabase.select_one(
        "customer_organizations", "id,owner_user_id,tenant_id",
        id=organization_id, owner_user_id=user_id,
    )
    if not member and not org:
        raise HTTPException(404, detail="service_request_not_found")
    return row, {"organization_id": organization_id, "tenant_id": (org or {}).get("tenant_id")}


@router.get("/customer/service-requests/{request_id}/result")
async def customer_service_request_result(request_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id:
        raise HTTPException(404, detail="service_request_not_found")
    row, _ = await _customer_request_access(request_id, p.user_id)
    result = row.get("result") or {}
    return {
        "request_id": row["id"], "service": row["service_key"], "target": row.get("target"),
        "target_type": row.get("target_type"), "status": row["status"],
        "processing_state": row.get("processing_state") or "queued",
        "findings": result.get("findings", []), "evidence": result.get("evidence", []),
        "sources_checked": result.get("sources_checked", []),
        "sources_unavailable": result.get("sources_unavailable", []),
        "recommendations": result.get("recommendations", []), "case_id": result.get("case_id"),
        "created_at": row.get("created_at"), "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"), "failure_code": row.get("failure_code"),
        "result": result,
    }


@router.get("/customer/service-requests/{request_id}")
async def customer_service_request_detail(request_id: str, p: DeveloperPrincipal=Depends(principal)):
    if not p.user_id:
        raise HTTPException(404, detail="service_request_not_found")
    row, _ = await _customer_request_access(request_id, p.user_id)
    return {
        "request_id": row["id"], "service": row["service_key"], "target": row.get("target"),
        "target_type": row.get("target_type"), "status": row["status"],
        "processing_state": row.get("processing_state") or "queued",
        "attempts": row.get("attempts", 0), "failure_code": row.get("failure_code"),
        "created_at": row.get("created_at"), "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"), "result": row.get("result") or {},
        "poll_url": f"/api/v1/customer/service-requests/{row['id']}/result",
    }


@router.get("/customer/service-requests")
async def service_requests(p:DeveloperPrincipal=Depends(principal)):
    if not p.user_id:
        raise HTTPException(401, detail="authentication_required")
    memberships=await supabase.select("organization_members","organization_id",user_id=p.user_id,status="active")
    orgs=await supabase.select("customer_organizations","id",owner_user_id=p.user_id)
    org_ids=list({str(r["organization_id"]) for r in memberships} | {str(r["id"]) for r in orgs})
    rows=[]
    for org_id in org_ids:
        rows.extend(await supabase.select(
            "service_requests",
            "id,organization_id,requester_user_id,service_key,urgency,description,target,target_type,status,processing_state,attempts,failure_code,created_at,updated_at",
            organization_id=org_id,
        ))
    return {"service_requests":rows}


@router.post("/customer/service-requests")
async def create_service_request(body:ServiceRequest,p:DeveloperPrincipal=Depends(principal)):
    if not p.user_id:
        raise HTTPException(401,detail="authentication_required")
    if body.service_key not in {"cybersecurity_assessment","incident_response","threat_intelligence","brand_protection","dark_web_monitoring","soc_mdr","ai_security","physical_security","compliance","mobile_digital_intelligence","other"}:
        raise HTTPException(400,detail="invalid_service_key")
    if body.urgency not in {"low","normal","high","critical"}:
        raise HTTPException(400,detail="invalid_urgency")
    organization_id=body.organization_id
    if organization_id:
        member=await supabase.select_one(
            "organization_members","organization_id,user_id,role,status",
            organization_id=organization_id,user_id=p.user_id,status="active",
        )
        org=await supabase.select_one(
            "customer_organizations","id,owner_user_id,tenant_id,admission_status",
            id=organization_id,owner_user_id=p.user_id,
        )
        if not org and not member:
            raise HTTPException(404,detail="organization_not_found")
        if member and member.get("role") not in {"owner","admin","requester"} and not org:
            raise HTTPException(403,detail="service_request_role_required")
        if not org:
            org=await supabase.select_one(
                "customer_organizations","id,owner_user_id,tenant_id,admission_status",
                id=organization_id,
            )
    else:
        org=await supabase.select_one("customer_organizations","id,tenant_id,admission_status",owner_user_id=p.user_id,organization_type="individual")
        if not org:
            org_id=await supabase.rpc("create_customer_organization_for_user",{
                "p_owner_user_id":p.user_id,"p_type":"individual","p_legal_name":"Personal Workspace",
                "p_country_code":None,"p_domain":None,"p_registration_number":None,
            })
            org=await supabase.select_one("customer_organizations","id,tenant_id,admission_status",id=str(org_id),owner_user_id=p.user_id)
        organization_id=str(org["id"]) if org else None
    if not org or not org.get("tenant_id"):
        raise HTTPException(409,detail="organization_tenant_required")
    description=body.description.strip()
    target=body.target.strip() if body.target else ""
    target_type=(body.target_type or ("domain" if body.service_key=="dark_web_monitoring" else "url")).strip().lower()
    if not target:
        match=re.search(r"^Target:\s*(.+)$",description,re.MULTILINE|re.IGNORECASE)
        target=match.group(1).strip() if match else ""
    if body.service_key=="dark_web_monitoring":
        if not target:
            raise HTTPException(422,detail="dark_web_target_required")
        target=_normalize_customer_target(target,target_type)
    elif target:
        target=_normalize_customer_target(target,target_type)
    row=await supabase.insert_one("service_requests",{
        "organization_id":organization_id,"requester_user_id":p.user_id,
        "service_key":body.service_key,"urgency":body.urgency,"description":description,
        "target":target or None,"target_type":target_type if target else None,
        "status":"submitted",
        "processing_state":"queued" if body.service_key=="dark_web_monitoring" else "succeeded",
        "result":{} if body.service_key=="dark_web_monitoring" else None,
    })
    if body.service_key=="dark_web_monitoring":
        return {
            "request_id":row["id"],"service":body.service_key,"target":target,"target_type":target_type,
            "status":row.get("status","submitted"),"processing_state":row.get("processing_state","queued"),
            "poll_url":f"/api/v1/customer/service-requests/{row['id']}/result",
        }
    # Preserve the existing synchronous passive-assessment path for other services.
    if body.service_key=="cybersecurity_assessment":
        from urllib.parse import urlsplit
        from cyclothone.web.crawler import WebCrawler
        target_url=target or ""
        if not target_url:
            match=re.search(r"^Target:\\s*(.+)$",description,re.MULTILINE|re.IGNORECASE)
            target_url=match.group(1).strip() if match else ""
        if not target_url:
            await supabase.update("service_requests",{"status":"blocked","processing_state":"blocked","failure_code":"cybersecurity_target_required"},id=str(row["id"]))
            raise HTTPException(422,detail="cybersecurity_target_required")
        target_url=target_url if "://" in target_url else f"https://{target_url}"
        parsed=urlsplit(target_url)
        if parsed.scheme not in {"http","https"} or not parsed.hostname:
            await supabase.update("service_requests",{"status":"blocked","processing_state":"blocked","failure_code":"invalid_cybersecurity_target"},id=str(row["id"]))
            raise HTTPException(422,detail="invalid_cybersecurity_target")
        try:
            pages=await WebCrawler().crawl(target_url,layer="surface",respect_robots=False,depth=0)
            if not pages:
                await supabase.update("service_requests",{"status":"blocked","processing_state":"blocked","failure_code":"target_unreachable"},id=str(row["id"]))
                raise HTTPException(502,detail="target_unreachable")
            page=pages[0]
            findings=[]
            if page.status_code>=400: findings.append({"severity":"high","title":"Target returned an error HTTP status","evidence":{"status_code":page.status_code}})
            if page.credential_indicators: findings.append({"severity":"critical","title":"Credential-pattern indicators exposed in public content","evidence":{"count":page.credential_indicators}})
            if page.wallets: findings.append({"severity":"high","title":"Cryptocurrency wallet indicators exposed in public content","evidence":{"count":len(page.wallets)}})
            if page.emails: findings.append({"severity":"medium","title":"Email addresses exposed in public content","evidence":{"count":len(page.emails)}})
            if not findings: findings.append({"severity":"informational","title":"No configured public-content exposure indicators observed","evidence":{"status_code":page.status_code,"content_type":page.content_type}})
            summary={"target":str(page.url),"status_code":page.status_code,"content_type":page.content_type,
                "observed_emails":len(page.emails),"observed_urls":len(page.urls),"observed_wallets":len(page.wallets),
                "credential_indicators":page.credential_indicators,"finding_count":len(findings),"findings":findings,
                "method":"bounded passive public HTTP assessment"}
            await supabase.update("service_requests",{"status":"resolved","processing_state":"succeeded","result":summary,"completed_at":datetime.now(UTC).isoformat()},id=str(row["id"]))
            return {**row,"status":"resolved","processing_state":"succeeded","result":summary}
        except HTTPException:
            raise
        except Exception:
            await supabase.update("service_requests",{"status":"blocked","processing_state":"failed","failure_code":"cybersecurity_assessment_unavailable"},id=str(row["id"]))
            raise HTTPException(503,detail="cybersecurity_assessment_unavailable")
    return row
