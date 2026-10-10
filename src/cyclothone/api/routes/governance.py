from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/governance", tags=["governance"])


class PrivacyRequestCreate(BaseModel):
    request_type: str = Field(pattern="^(access|rectification|erasure|restriction|portability|objection)$")
    # Must be a non-reversible internal subject reference, never an email/address/document number.
    subject_ref: str = Field(min_length=8, max_length=256)
    request_summary: str = Field(min_length=1, max_length=2000)
    due_at: datetime | None = None


class PrivacyRequestTransition(BaseModel):
    status: str = Field(pattern="^(received|triage|in_progress|fulfilled|rejected)$")
    resolution_summary: str | None = Field(default=None, max_length=2000)
    due_at: datetime | None = None


def _tenant(principal: DeveloperPrincipal) -> str:
    return str(UUID(principal.tenant_id))


class RetentionPolicyCreate(BaseModel):
    resource_type: str = Field(pattern="^[a-z][a-z0-9_.-]{1,79}$")
    retention_days: int = Field(ge=1, le=36500)
    enabled: bool = False
    legal_basis: str = Field(min_length=3, max_length=1000)


class LegalHoldCreate(BaseModel):
    resource_type: str = Field(pattern="^[a-z][a-z0-9_.-]{1,79}$")
    resource_ref: str = Field(min_length=8, max_length=256)
    reason: str = Field(min_length=5, max_length=2000)
    expires_at: datetime | None = None


@router.post("/retention-policies", status_code=status.HTTP_201_CREATED)
async def create_retention_policy(body: RetentionPolicyCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("governance:manage",))
    tenant_id = _tenant(principal)
    row = {"tenant_id": tenant_id, "resource_type": body.resource_type, "retention_days": body.retention_days,
           "enabled": body.enabled, "legal_basis": body.legal_basis.strip(), "created_by": principal.user_id,
           "updated_by": principal.user_id}
    try:
        async def _insert():
            return await (await supabase._ensure()).table("governance_retention_policies").insert(row).select("*").execute()
        rows = (await supabase._retry(_insert, attempts=2)).data or []
        if not rows:
            raise RuntimeError("insert returned no policy")
        return rows[0]
    except Exception as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "policy already exists or could not be recorded") from exc


@router.get("/retention-policies")
async def list_retention_policies(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("governance:read",))
    async def _do():
        return await (await supabase._ensure()).table("governance_retention_policies").select(
            "id,resource_type,retention_days,enabled,legal_basis,created_at,updated_at"
        ).eq("tenant_id", _tenant(principal)).order("resource_type").execute()
    try:
        return list((await supabase._retry(_do, attempts=2)).data or [])
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "retention policies could not be loaded") from exc


@router.post("/legal-holds", status_code=status.HTTP_201_CREATED)
async def create_legal_hold(body: LegalHoldCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("governance:manage",))
    tenant_id = _tenant(principal)
    if body.expires_at and body.expires_at.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "expires_at must include a timezone")
    row = {"tenant_id": tenant_id, "resource_type": body.resource_type, "resource_ref": body.resource_ref.strip(),
           "reason": body.reason.strip(), "expires_at": body.expires_at.astimezone(UTC).isoformat() if body.expires_at else None,
           "created_by": principal.user_id}
    try:
        async def _insert():
            return await (await supabase._ensure()).table("governance_legal_holds").insert(row).select(
                "id,resource_type,resource_ref,reason,active,expires_at,created_at"
            ).execute()
        rows = (await supabase._retry(_insert, attempts=2)).data or []
        if not rows:
            raise RuntimeError("insert returned no hold")
        return rows[0]
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "legal hold could not be recorded") from exc


@router.get("/legal-holds")
async def list_legal_holds(active: bool | None = None, principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("governance:read",))
    async def _do():
        query = (await supabase._ensure()).table("governance_legal_holds").select(
            "id,resource_type,resource_ref,reason,active,expires_at,created_at,released_at"
        ).eq("tenant_id", _tenant(principal)).order("created_at", desc=True)
        if active is not None:
            query = query.eq("active", active)
        return await query.execute()
    try:
        return list((await supabase._retry(_do, attempts=2)).data or [])
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "legal holds could not be loaded") from exc


@router.post("/legal-holds/{hold_id}/release")
async def release_legal_hold(hold_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("governance:manage",))
    tenant_id = _tenant(principal)
    async def _update():
        return await (await supabase._ensure()).table("governance_legal_holds").update(
            {"active": False, "released_by": principal.user_id, "released_at": datetime.now(UTC).isoformat()}
        ).eq("id", str(hold_id)).eq("tenant_id", tenant_id).eq("active", True).select(
            "id,resource_type,resource_ref,active,expires_at,created_at,released_at"
        ).limit(1).execute()
    try:
        rows = (await supabase._retry(_update, attempts=2)).data or []
        if not rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "active legal hold not found")
        return rows[0]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "legal hold could not be released") from exc


@router.post("/privacy-requests", status_code=status.HTTP_201_CREATED)
async def create_privacy_request(
    body: PrivacyRequestCreate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict:
    principal.require(("privacy:manage",))
    tenant_id = _tenant(principal)
    due_at = body.due_at
    if due_at and due_at.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "due_at must include a timezone")
    row = {
        "tenant_id": tenant_id,
        "request_type": body.request_type,
        "subject_ref": body.subject_ref.strip(),
        "request_summary": body.request_summary.strip(),
        "due_at": due_at.astimezone(UTC).isoformat() if due_at else None,
        "created_by": principal.user_id,
        "updated_by": principal.user_id,
    }
    try:
        async def _insert():
            return await (await supabase._ensure()).table("governance_privacy_requests").insert(row).select(
                "id,request_type,subject_ref,status,request_summary,due_at,resolution_summary,created_at,updated_at,resolved_at"
            ).execute()
        rows = (await supabase._retry(_insert, attempts=2)).data or []
        if not rows:
            raise RuntimeError("insert returned no privacy request row")
        return rows[0]
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "privacy request could not be recorded") from exc


@router.get("/privacy-requests")
async def list_privacy_requests(
    request_status: str | None = Query(default=None, alias="status", pattern="^(received|triage|in_progress|fulfilled|rejected)$"),
    limit: int = Query(default=50, ge=1, le=200),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict]:
    principal.require(("privacy:read",))
    tenant_id = _tenant(principal)
    async def _do():
        query = (await supabase._ensure()).table("governance_privacy_requests").select(
            "id,request_type,subject_ref,status,request_summary,due_at,resolution_summary,created_at,updated_at,resolved_at"
        ).eq("tenant_id", tenant_id).order("created_at", desc=True).limit(limit)
        if request_status:
            query = query.eq("status", request_status)
        return await query.execute()
    try:
        return list((await supabase._retry(_do, attempts=2)).data or [])
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "privacy requests could not be loaded") from exc


@router.post("/privacy-requests/{request_id}/transition")
async def transition_privacy_request(
    request_id: UUID,
    body: PrivacyRequestTransition,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict:
    principal.require(("privacy:manage",))
    tenant_id = _tenant(principal)
    async def _find():
        return await (await supabase._ensure()).table("governance_privacy_requests").select(
            "id,status,tenant_id,due_at,resolution_summary"
        ).eq("id", str(request_id)).eq("tenant_id", tenant_id).limit(1).execute()
    try:
        rows = (await supabase._retry(_find, attempts=2)).data or []
        if not rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "privacy request not found")
        current = rows[0]["status"]
        allowed = {
            "received": {"triage", "rejected"},
            "triage": {"in_progress", "rejected"},
            "in_progress": {"fulfilled", "rejected", "triage"},
            "fulfilled": set(),
            "rejected": set(),
        }
        if body.status != current and body.status not in allowed[current]:
            raise HTTPException(status.HTTP_409_CONFLICT, f"invalid transition: {current} -> {body.status}")
        if body.status in {"fulfilled", "rejected"} and not (body.resolution_summary or "").strip():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "resolution_summary is required for a terminal state")
        if body.due_at and body.due_at.tzinfo is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "due_at must include a timezone")
        now = datetime.now(UTC).isoformat()
        patch = {
            "status": body.status,
            "resolution_summary": body.resolution_summary.strip() if body.resolution_summary is not None else rows[0].get("resolution_summary"),
            "due_at": body.due_at.astimezone(UTC).isoformat() if body.due_at else rows[0].get("due_at"),
            "updated_by": principal.user_id,
            "updated_at": now,
            "resolved_at": now if body.status in {"fulfilled", "rejected"} else None,
        }
        async def _update():
            return await (await supabase._ensure()).table("governance_privacy_requests").update(patch).eq(
                "id", str(request_id)
            ).eq("tenant_id", tenant_id).eq("status", current).select(
                "id,request_type,subject_ref,status,request_summary,due_at,resolution_summary,created_at,updated_at,resolved_at"
            ).limit(1).execute()
        updated = (await supabase._retry(_update, attempts=2)).data or []
        if not updated:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "privacy request not found")
        return updated[0]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "privacy request could not be updated") from exc
