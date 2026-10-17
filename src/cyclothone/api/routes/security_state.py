from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from cyclothone.api.routes.customer_identity import principal, ServiceRequest, create_service_request
from cyclothone.developer.auth import DeveloperPrincipal
from cyclothone.storage.supabase_client import supabase

router = APIRouter(tags=["customer-security-state"])

async def _authorized_org_ids(user_id: str) -> list[str]:
    owned = await supabase.select("customer_organizations", "id", owner_user_id=user_id)
    memberships = await supabase.select("organization_members", "organization_id", user_id=user_id, status="active")
    return sorted({str(x["id"]) for x in owned if x.get("id")} |
                  {str(x["organization_id"]) for x in memberships if x.get("organization_id")})

@router.get("/customer/security-state")
async def list_security_state(p: DeveloperPrincipal = Depends(principal)):
    if not p.user_id:
        raise HTTPException(403, detail="user_identity_required")
    org_ids = await _authorized_org_ids(p.user_id)
    if not org_ids:
        return {"claims": [], "count": 0}
    client = await supabase._ensure()
    response = await (client.table("security_claims").select(
        "id,organization_id,target_key,claim_type,status,coverage_status,severity,title,statement,"
        "confidence,sources_checked,sources_unavailable,finding_count,high_finding_count,"
        "origin_service_key,origin_request_id,version,observed_at,updated_at,evidence"
    ).in_("organization_id", org_ids).eq("status", "active").order("updated_at", desc=True).limit(100).execute())
    claims = getattr(response, "data", None) or []
    return {"claims": claims, "count": len(claims)}

@router.get("/customer/security-state/claims/{claim_id}")
async def get_security_claim(claim_id: str, p: DeveloperPrincipal = Depends(principal)):
    if not p.user_id:
        raise HTTPException(403, detail="user_identity_required")
    org_ids = await _authorized_org_ids(p.user_id)
    if not org_ids:
        raise HTTPException(404, detail="claim_not_found")
    client = await supabase._ensure()
    response = await (client.table("security_claims").select("*")
        .eq("id", claim_id).in_("organization_id", org_ids).maybe_single().execute())
    claim = getattr(response, "data", None)
    if not isinstance(claim, dict):
        raise HTTPException(404, detail="claim_not_found")
    history_response = await (client.table("security_claim_history").select("*")
        .eq("claim_id", claim_id).eq("organization_id", claim["organization_id"])
        .order("version", desc=True).limit(100).execute())
    return {"claim": claim, "history": getattr(history_response, "data", None) or []}

class RecheckRequest(BaseModel):
    claim_id: str

@router.post("/customer/security-state/recheck")
async def recheck_security_claim(body: RecheckRequest, p: DeveloperPrincipal = Depends(principal)):
    if not p.user_id:
        raise HTTPException(403, detail="user_identity_required")
    org_ids = await _authorized_org_ids(p.user_id)
    if not org_ids:
        raise HTTPException(404, detail="claim_not_found")
    client = await supabase._ensure()
    response = await (client.table("security_claims").select(
        "id,organization_id,target_key,claim_type,status"
    ).eq("id", body.claim_id).in_("organization_id", org_ids)
     .eq("status", "active").maybe_single().execute())
    claim = getattr(response, "data", None)
    if not isinstance(claim, dict):
        raise HTTPException(404, detail="claim_not_found")
    # Existing request creation is the only allowed execution path.
    service_key = "dark_web_monitoring" if claim["claim_type"] == "dark_web_exposure" else "cybersecurity_assessment"
    request = ServiceRequest(
        organization_id=str(claim["organization_id"]),
        service_key=service_key,
        urgency="normal",
        description=f"Target: {claim['target_key']}\nService objective: recheck claim {claim['id']}",
    )
    result = await create_service_request(request, p)
    return {"from_claim_id": claim["id"], "service_request": result}
