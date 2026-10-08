from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from cyclothone.api.routes.customer_identity import principal as customer_principal
from cyclothone.developer.auth import DeveloperPrincipal
from cyclothone.storage.supabase_client import supabase

router=APIRouter(prefix="/mobile-intelligence",tags=["mobile-intelligence"])

@router.get("/cases/{case_id}/attribution")
async def case_attribution(case_id:str,p:DeveloperPrincipal=Depends(customer_principal)):
    if not p.tenant_id:
        raise HTTPException(403,"workspace_not_admitted")
    case=await supabase.select_one("crime_cases","id,tenant_id,case_number,title,status,severity",id=case_id,tenant_id=p.tenant_id)
    if not case:
        raise HTTPException(404,"case_not_found")
    ttps=await supabase.select("mdi_case_ttps","id,technique_id,observed_at,confidence,evidence_ref,detector,raw",case_id=case_id,tenant_id=p.tenant_id)
    attrs=await supabase.select("mdi_attribution","id,actor_id,confidence,method,evidence,alternative_actors,computed_at",case_id=case_id,tenant_id=p.tenant_id)
    actor_ids=[a.get("actor_id") for a in attrs if a.get("actor_id")]
    actors=[]
    for actor_id in actor_ids:
        actor=await supabase.select_one("mdi_threat_actors","id,actor_id,name,aliases,origin_country,motivation,sophistication",id=actor_id)
        if actor:
            actors.append(actor)
    return {"case":case,"ttps":ttps,"attributions":attrs,"actors":actors}
