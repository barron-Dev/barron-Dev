from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.brand.takedown import TakedownService
from cyclothone.brand.typosquat import TyposquatScanner
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/brand", tags=["brand"])
_takedown = TakedownService()


def _tenant(principal: DeveloperPrincipal, scope: str) -> str:
    principal.require((scope,))
    return str(principal.tenant_id)


class BrandCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    primary_domain: str = Field(min_length=3, max_length=253)
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    trademarks: list[str] = Field(default_factory=list)
    social_handles: list[str] = Field(default_factory=list)
    app_ids: dict = Field(default_factory=dict)
    logo_url: str | None = Field(default=None, max_length=2048)
    region_code: str | None = Field(default=None, min_length=2, max_length=8)
    similarity_min: float = Field(default=0.75, ge=0.5, le=0.99)


@router.post("/brands", status_code=201)
async def create_brand(
    brand: BrandCreate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:manage")
    row = brand.model_dump()
    row.update(
        tenant_id=tenant_id,
        primary_domain=brand.primary_domain.lower().strip().rstrip("."),
    )

    async def query():
        return await (
            await supabase._ensure()
        ).table("brands").insert(row).execute()

    try:
        data = (await supabase._retry(query, attempts=2)).data or []
    except Exception as exc:
        message = str(exc)
        if "23505" in message or "unique constraint" in message.lower():
            raise HTTPException(409, "brand domain already registered for this tenant") from exc
        raise HTTPException(502, "brand registration persistence failed") from exc
    if not data:
        raise HTTPException(502, "brand registration returned no persisted row")
    return data[0]


@router.get("/brands")
async def list_brands(
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:read")

    async def query():
        return await (
            await supabase._ensure()
        ).table("brands").select("*").eq("tenant_id", tenant_id).order(
            "created_at", desc=True
        ).execute()

    return list((await supabase._retry(query, attempts=2)).data or [])


@router.get("/threats")
async def list_threats(
    brand_id: UUID | None = None,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    kind: str | None = None,
    verification_state: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:read")
    if verification_state and verification_state not in {
        "candidate", "verified", "false_positive"
    }:
        raise HTTPException(422, "invalid verification_state")

    async def query():
        result = (
            await supabase._ensure()
        ).table("brand_threats").select("*").eq("tenant_id", tenant_id)
        if brand_id:
            result = result.eq("brand_id", str(brand_id))
        if status_filter:
            result = result.eq("status", status_filter)
        if severity:
            result = result.eq("severity", severity)
        if kind:
            result = result.eq("kind", kind)
        if verification_state:
            result = result.eq("verification_state", verification_state)
        return await result.order("first_seen_at", desc=True).limit(limit).execute()

    return list((await supabase._retry(query, attempts=2)).data or [])


@router.get("/stats")
async def brand_stats(
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:read")

    async def query():
        return await (
            await supabase._ensure()
        ).table("brand_threats").select(
            "kind,severity,status,verification_state"
        ).eq("tenant_id", tenant_id).execute()

    rows = (await supabase._retry(query, attempts=2)).data or []
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    for row in rows:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        state = row.get("verification_state") or "candidate"
        by_verification[state] = by_verification.get(state, 0) + 1
    active_statuses = {"open", "investigating", "monitoring", "takedown_requested"}
    return {
        "total": len(rows),
        "active": sum(row["status"] in active_statuses for row in rows),
        "candidate": by_verification.get("candidate", 0),
        "verified": by_verification.get("verified", 0),
        "false_positive": by_verification.get("false_positive", 0),
        "by_verification_state": by_verification,
        "by_kind": by_kind,
        "by_severity": by_severity,
    }


@router.post("/brands/{brand_id}/scan-typosquat")
async def scan_typosquat(
    brand_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:scan")

    async def query():
        return await (
            await supabase._ensure()
        ).table("brands").select("*").eq("id", str(brand_id)).eq(
            "tenant_id", tenant_id
        ).limit(1).execute()

    rows = (await supabase._retry(query, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "brand not found")
    return await TyposquatScanner().scan_brand(rows[0])


class ThreatUpdate(BaseModel):
    status: str | None = Field(
        default=None,
        pattern="^(open|investigating|monitoring|takedown_requested|taken_down|false_positive|resolved)$",
    )


@router.patch("/threats/{threat_id}")
async def update_threat(
    threat_id: UUID,
    update: ThreatUpdate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:manage")
    if not update.status:
        raise HTTPException(400, "nothing to update")
    values: dict[str, object] = {"status": update.status}
    if update.status == "false_positive":
        values["verification_state"] = "false_positive"
        values["false_positive_at"] = datetime.now(UTC).isoformat()

    async def query():
        return await (
            await supabase._ensure()
        ).table("brand_threats").update(values).eq(
            "id", str(threat_id)
        ).eq("tenant_id", tenant_id).execute()

    data = (await supabase._retry(query, attempts=2)).data or []
    if not data:
        raise HTTPException(404, "threat not found")
    return data[0]


class TakedownRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=40)


@router.post("/threats/{threat_id}/takedown")
async def prepare_takedown(
    threat_id: UUID,
    request: TakedownRequest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    tenant_id = _tenant(principal, "brand:takedown")
    try:
        return await _takedown.prepare_request(
            tenant_id=UUID(tenant_id),
            threat_id=threat_id,
            provider=request.provider,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, "takedown preparation could not be persisted") from exc
