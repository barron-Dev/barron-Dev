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
        return await supabase.insert_one("governance_privacy_requests", row)
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
            "id,status,tenant_id"
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
            "resolution_summary": body.resolution_summary.strip() if body.resolution_summary else None,
            "due_at": body.due_at.astimezone(UTC).isoformat() if body.due_at else None,
            "updated_by": principal.user_id,
            "updated_at": now,
            "resolved_at": now if body.status in {"fulfilled", "rejected"} else None,
        }
        async def _update():
            return await (await supabase._ensure()).table("governance_privacy_requests").update(patch).eq(
                "id", str(request_id)
            ).eq("tenant_id", tenant_id).select(
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
