from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field

from sentinel.api.deps import get_principal, require_role
from sentinel.security.jwt import Principal
from sentinel.physical.correlator import PhysicalCorrelator
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/physical", tags=["physical"])
correlator = PhysicalCorrelator()


class SiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    address: str | None = Field(default=None, max_length=500)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    timezone: str = Field(default="UTC", max_length=64)
    acs_kind: str | None = Field(default=None, max_length=32)
    acs_endpoint: str | None = Field(default=None, max_length=2048)
    acs_auth_ref: str | None = Field(default=None, max_length=256)
    cctv_kind: str | None = Field(default=None, max_length=32)
    cctv_endpoint: str | None = Field(default=None, max_length=2048)
    cctv_auth_ref: str | None = Field(default=None, max_length=256)
    iot_kind: str | None = Field(default=None, max_length=32)
    iot_endpoint: str | None = Field(default=None, max_length=2048)
    iot_auth_ref: str | None = Field(default=None, max_length=256)


@router.post("/sites", status_code=201)
async def create_site(body: SiteCreate, principal: Principal = Depends(require_role("owner", "admin"))):
    row = {"tenant_id": str(principal.tenant_id), **body.model_dump()}
    async def _do():
        client = await supabase._ensure()
        return await client.table("physical_sites").insert(row).execute()
    return (await supabase._retry(_do)).data[0]


@router.get("/sites")
async def list_sites(principal: Principal = Depends(get_principal)):
    async def _do():
        client = await supabase._ensure()
        return await client.table("physical_sites").select("id,name,address,country,timezone,acs_kind,cctv_kind,iot_kind,enabled,created_at").eq("tenant_id", str(principal.tenant_id)).order("created_at", desc=True).execute()
    return list((await supabase._retry(_do)).data or [])


@router.get("/correlations")
async def list_correlations(status: str | None = None, severity: str | None = None, pattern: str | None = None, limit: int = Query(200, ge=1, le=1000), principal: Principal = Depends(get_principal)):
    async def _do():
        client = await supabase._ensure()
        q = client.table("physical_digital_correlations").select("*").eq("tenant_id", str(principal.tenant_id))
        if status: q = q.eq("status", status)
        if severity: q = q.eq("severity", severity)
        if pattern: q = q.eq("pattern", pattern)
        return await q.order("first_seen", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do)).data or [])


@router.post("/correlations/run")
async def run_correlation(window_minutes: int = Query(15, ge=1, le=120), principal: Principal = Depends(require_role("owner", "admin"))):
    return await correlator.run_window(principal.tenant_id, window_minutes)


class CorrelationUpdate(BaseModel):
    status: str = Field(pattern="^(new|acknowledged|investigating|resolved|false_positive)$")


@router.patch("/correlations/{corr_id}")
async def update_correlation(corr_id: UUID, body: CorrelationUpdate, principal: Principal = Depends(require_role("owner", "admin", "member"))):
    async def _do():
        client = await supabase._ensure()
        return await client.table("physical_digital_correlations").update({"status": body.status, "last_seen": "now()"}).eq("id", str(corr_id)).eq("tenant_id", str(principal.tenant_id)).execute()
    data = (await supabase._retry(_do)).data or []
    if not data: raise HTTPException(404, "correlation not found")
    return data[0]


@router.get("/stats")
async def stats(principal: Principal = Depends(get_principal)):
    rows = await list_correlations(limit=1000, principal=principal)
    by_pattern: dict[str, int] = {}; by_severity: dict[str, int] = {}
    for row in rows:
        by_pattern[row["pattern"]] = by_pattern.get(row["pattern"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
    return {"total": len(rows), "new": sum(r["status"] == "new" for r in rows), "by_pattern": by_pattern, "by_severity": by_severity}
