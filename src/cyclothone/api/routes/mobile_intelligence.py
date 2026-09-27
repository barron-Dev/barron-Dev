from __future__ import annotations

from datetime import UTC, datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.mobile_intelligence.service import MobileIntelligenceError, MobileIntelligenceService, CAPABILITIES, subject_hash
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/mobile-intelligence", tags=["mobile-intelligence"])
service = MobileIntelligenceService()


def principal(p: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    p.require(("mobile:intelligence",))
    return p


class AuthorizationRequest(BaseModel):
    purpose: str = Field(min_length=3, max_length=120)
    authority_reference: str = Field(min_length=3, max_length=240)
    number: str = Field(min_length=7, max_length=20)
    valid_hours: int = Field(default=24, ge=1, le=720)


class IntelligenceRequest(BaseModel):
    number: str = Field(min_length=7, max_length=20)
    capabilities: list[str] = Field(min_length=1, max_length=20)
    purpose: str = Field(min_length=3, max_length=120)
    authority_reference: str = Field(min_length=3, max_length=240)
    authorization_id: str
    max_age_hours: int = Field(default=24, ge=1, le=720)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    radius_km: int | None = Field(default=None, ge=1, le=100)


@router.get("/capabilities")
async def capabilities(p: DeveloperPrincipal = Depends(principal)):
    return {"service": "mobile_digital_intelligence", "capabilities": sorted(CAPABILITIES)}


@router.get("/status")
async def status(p: DeveloperPrincipal = Depends(principal)):
    return await service.status(__import__("uuid").UUID(p.tenant_id))


@router.post("/authorizations", status_code=201)
async def create_authorization(body: AuthorizationRequest, p: DeveloperPrincipal = Depends(principal)):
    normalized = body.number.strip()
    try:
        subject = subject_hash(normalized)
    except Exception:
        raise HTTPException(422, "invalid_number")
    # Creation is deliberately operator-controlled: API clients cannot self-approve authority.
    row = await supabase.insert_one("mobile_authorizations", {
        "tenant_id": p.tenant_id, "app_id": p.app_id, "subject_hash": subject,
        "purpose": body.purpose.strip(), "authority_reference": body.authority_reference.strip(),
        "valid_from": datetime.now(UTC).isoformat(), "valid_to": (datetime.now(UTC) + timedelta(hours=body.valid_hours)).isoformat(),
        "status": "pending", "requested_by": p.user_id,
    })
    return {"id": str(row["id"]), "status": "pending", "message": "Operator approval is required before mobile intelligence can run."}


@router.post("/query")
async def query(body: IntelligenceRequest, p: DeveloperPrincipal = Depends(principal)):
    try:
        return await service.query(__import__("uuid").UUID(p.tenant_id), p.app_id, body.number, body.capabilities, body.purpose, body.authority_reference, body.authorization_id, body.max_age_hours, body.latitude, body.longitude, body.radius_km)
    except MobileIntelligenceError as exc:
        detail = str(exc)
        status = 403 if "authorization" in detail else 422
        if detail.startswith("provider_") or detail.startswith("no_enabled_mobile_provider"):
            status = 503
        raise HTTPException(status, detail)


@router.get("/queries/{query_id}")
async def query_detail(query_id: str, p: DeveloperPrincipal = Depends(principal)):
    row = await supabase.select_one("mobile_queries", "id,status,capabilities,subject_hash,requested_at,completed_at,error_code", id=query_id, tenant_id=p.tenant_id, app_id=p.app_id)
    if not row: raise HTTPException(404, "query_not_found")
    observations = await supabase.select("mobile_observations", "id,provider_id,capability,data,observed_at", query_id=query_id)
    return {"query": row, "observations": observations}
