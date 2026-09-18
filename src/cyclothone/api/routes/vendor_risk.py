from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sentinel.compliance.vendor_risk import VendorRiskScorer
from sentinel.developer.auth import DeveloperPrincipal, authenticate_request
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/vendor-risk", tags=["vendor-risk"])
_scorer = VendorRiskScorer()

class VendorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category: str = Field(pattern=r"^(cloud|saas|contractor|hardware|other)$")
    criticality: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    data_access: list[str] = Field(default_factory=list, max_length=20)
    soc2: bool = False
    iso27001: bool = False
    hipaa: bool = False
    gdpr: bool = False
    pci: bool = False
    notes: str | None = Field(default=None, max_length=10000)

async def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("compliance:read",))
    return principal

@router.post("/vendors", status_code=201)
async def create_vendor(body: VendorCreate, principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    principal.require(("compliance:run",))
    row = {**body.model_dump(), "tenant_id": principal.tenant_id}
    async def _do():
        return await (await supabase._ensure()).table("vendors").insert(row).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    return rows[0] if rows else {"created": False}

@router.get("/vendors")
async def list_vendors(principal: DeveloperPrincipal = Depends(_principal)) -> list[dict]:
    async def _do():
        return await (await supabase._ensure()).table("vendors").select("*").eq("tenant_id", principal.tenant_id).order("criticality", desc=True).execute()
    return [{**v, "risk_score": (s := _scorer.score(v)).score, "risk_band": s.band, "risk_reasons": s.reasons} for v in ((await supabase._retry(_do, attempts=2)).data or [])]

@router.post("/vendors/{vendor_id}/rescore")
async def rescore_vendor(vendor_id: UUID, principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    async def _do():
        return await (await supabase._ensure()).table("vendors").select("*").eq("id", str(vendor_id)).eq("tenant_id", principal.tenant_id).limit(1).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "vendor not found")
    result = _scorer.score(rows[0])
    return {"vendor_id": str(vendor_id), "score": result.score, "band": result.band, "reasons": result.reasons}
