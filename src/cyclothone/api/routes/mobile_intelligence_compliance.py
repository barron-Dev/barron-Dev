from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router=APIRouter(prefix="/mobile-intelligence/compliance",tags=["mobile-intelligence-compliance"])

@router.get("/findings")
async def findings(limit:int=Query(100,ge=1,le=200),principal:DeveloperPrincipal=Depends(authenticate_request)):
    principal.require(("mobile_intelligence:read",))
    if not principal.tenant_id: raise HTTPException(403,"workspace_not_admitted")
    return await supabase.select("mdi_compliance_findings","id,jurisdiction,rule_id,case_id,subject_id,severity,finding,evidence,remediated_at,detected_at",tenant_id=principal.tenant_id,limit=limit,order="detected_at.desc")

@router.post("/audit")
async def run_audit(principal:DeveloperPrincipal=Depends(authenticate_request)):
    principal.require(("mobile_intelligence:read",))
    if not principal.tenant_id: raise HTTPException(403,"workspace_not_admitted")
    results={}
    for fn in ("mdi_audit_retention","mdi_audit_lawful_basis","mdi_audit_cross_border","mdi_dsar_sla_breach"):
        results[fn]=await supabase.rpc(fn,{"p_tenant_id":principal.tenant_id})
    return {"tenant_id":principal.tenant_id,"results":results}
