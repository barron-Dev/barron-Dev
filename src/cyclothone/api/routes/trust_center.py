from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust-center", tags=["trust-center"])
public_router = APIRouter(prefix="/trust-center", tags=["trust-center-public"])

class TrustCenterConfig(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9-]{3,60}$")
    company_name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    logo_url: str | None = Field(default=None, max_length=2000)
    frameworks: list[str] = Field(default_factory=lambda: ["soc2"], max_length=20)
    security_email: str | None = Field(default=None, max_length=320)
    security_phone: str | None = Field(default=None, max_length=64)
    published: bool = False

@router.get("/config")
async def get_config(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:read",))
    async def _do():
        return await (await supabase._ensure()).table("trust_center").select("*").eq("tenant_id", principal.tenant_id).limit(1).execute()
    return ((await supabase._retry(_do, attempts=2)).data or [{}])[0]

@router.post("/config")
async def save_config(body: TrustCenterConfig, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:run",))
    row = {**body.model_dump(), "tenant_id": principal.tenant_id, "updated_at": datetime.now(UTC).isoformat()}
    async def _do():
        return await (await supabase._ensure()).table("trust_center").upsert(row, on_conflict="tenant_id").execute()
    return ((await supabase._retry(_do, attempts=2)).data or [{}])[0]

@public_router.get("/public/{slug}")
async def public_trust_center(slug: str) -> dict:
    async def _do():
        return await (await supabase._ensure()).table("trust_center").select("tenant_id,slug,company_name,logo_url,description,frameworks,security_email,updated_at").eq("slug", slug).eq("published", True).limit(1).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "not found")
    tc = rows[0]
    async def _status():
        return await (await supabase._ensure()).table("compliance_control_status").select("status,score").eq("tenant_id", tc["tenant_id"]).execute()
    statuses = (await supabase._retry(_status, attempts=2)).data or []
    applicable = [s for s in statuses if s.get("status") != "not_applicable"]
    passing = sum(s.get("status") == "passing" for s in applicable)
    return {"company_name": tc["company_name"], "description": tc["description"], "logo_url": tc["logo_url"], "frameworks": tc["frameworks"], "security_email": tc["security_email"], "updated_at": tc["updated_at"], "compliance_summary": {"score_percent": round((sum(float(s.get("score") or 0) for s in applicable) / len(applicable) * 100) if applicable else 0, 1), "controls_passing": passing, "controls_total": len(applicable)}}
