from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sentinel.developer.auth import DeveloperPrincipal, authenticate_request
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/auditor", tags=["auditor"])


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class EngagementCreate(BaseModel):
    framework_id: str = Field(min_length=2, max_length=64)
    auditor_firm: str = Field(min_length=1, max_length=200)
    auditor_lead: str = Field(min_length=1, max_length=200)
    auditor_email: str = Field(min_length=3, max_length=320)
    period_start: datetime
    period_end: datetime
    type: str = Field(pattern=r"^(type1|type2)$")


class QueryCreate(BaseModel):
    engagement_id: UUID
    control_id: UUID | None = None
    question: str = Field(min_length=1, max_length=10000)


class QueryAnswer(BaseModel):
    answer: str = Field(min_length=1, max_length=10000)
    status: str = Field(default="answered", pattern=r"^(answered|accepted|rejected)$")


async def _org_principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("compliance:read",))
    return principal


@router.post("/engagements", status_code=201)
async def create_engagement(body: EngagementCreate, principal: DeveloperPrincipal = Depends(_org_principal)) -> dict:
    principal.require(("compliance:run",))
    if body.period_start.tzinfo is None or body.period_end.tzinfo is None or body.period_end <= body.period_start:
        raise HTTPException(400, "invalid engagement period")
    owner = await supabase.select_one("developer_apps", "owner_user_id", id=principal.app_id)
    created_by = owner.get("owner_user_id") if owner else None
    row = {"tenant_id": principal.tenant_id, "framework_id": body.framework_id, "auditor_firm": body.auditor_firm, "auditor_lead": body.auditor_lead, "auditor_email": body.auditor_email, "period_start": body.period_start.isoformat(), "period_end": body.period_end.isoformat(), "type": body.type, "created_by": created_by}
    async def _do():
        return await (await supabase._ensure()).table("audit_engagements").insert(row).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(500, "engagement creation failed")
    return rows[0]


@router.get("/engagements")
async def list_engagements(principal: DeveloperPrincipal = Depends(_org_principal)) -> list[dict]:
    async def _do():
        return await (await supabase._ensure()).table("audit_engagements").select("*").eq("tenant_id", principal.tenant_id).order("period_start", desc=True).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/engagements/{engagement_id}/tokens", status_code=201)
async def issue_auditor_token(engagement_id: UUID, ttl_days: int = Query(30, ge=1, le=180), principal: DeveloperPrincipal = Depends(_org_principal)) -> dict:
    principal.require(("compliance:run",))
    async def _engagement():
        return await (await supabase._ensure()).table("audit_engagements").select("id").eq("id", str(engagement_id)).eq("tenant_id", principal.tenant_id).limit(1).execute()
    if not ((await supabase._retry(_engagement, attempts=2)).data or []):
        raise HTTPException(404, "engagement not found")
    raw = "aud_" + secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(days=ttl_days)
    owner = await supabase.select_one("developer_apps", "owner_user_id", id=principal.app_id)
    row = {"engagement_id": str(engagement_id), "tenant_id": principal.tenant_id, "token_hash": _hash(raw), "expires_at": expires.isoformat(), "created_by": owner.get("owner_user_id") if owner else None}
    async def _do():
        return await (await supabase._ensure()).table("auditor_access").insert(row).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    return {"id": rows[0]["id"] if rows else None, "token": raw, "expires_at": expires.isoformat()}


@router.post("/access/{access_id}/revoke")
async def revoke_auditor_token(access_id: UUID, principal: DeveloperPrincipal = Depends(_org_principal)) -> dict:
    principal.require(("compliance:run",))
    async def _do():
        return await (await supabase._ensure()).table("auditor_access").update({"revoked_at": datetime.now(UTC).isoformat()}).eq("id", str(access_id)).eq("tenant_id", principal.tenant_id).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "access token not found")
    return {"id": str(access_id), "revoked": True}


async def auditor_access(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing auditor token")
    token = authorization.split(" ", 1)[1].strip()
    if not token.startswith("aud_"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid auditor token")
    async def _do():
        return await (await supabase._ensure()).table("auditor_access").select("id,engagement_id,tenant_id,scopes,expires_at,revoked_at").eq("token_hash", _hash(token)).limit(1).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown auditor token")
    access = rows[0]
    expires = datetime.fromisoformat(str(access["expires_at"]).replace("Z", "+00:00"))
    if access.get("revoked_at") or expires <= datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "expired or revoked auditor token")
    return access


def _require_scope(access: dict, scope: str) -> None:
    if scope not in set(access.get("scopes") or []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "auditor scope not granted")


@router.get("/evidence")
async def auditor_evidence(framework: str | None = None, access: dict = Depends(auditor_access)) -> dict:
    _require_scope(access, "evidence:read")
    async def _do():
        q = (await supabase._ensure()).table("compliance_control_status").select("control_id,status,score,last_evaluated,evidence,evidence_valid_until,freshness_status").eq("tenant_id", access["tenant_id"])
        return await q.execute()
    rows = list((await supabase._retry(_do, attempts=2)).data or [])
    return {"engagement_id": access["engagement_id"], "tenant_id": access["tenant_id"], "framework": framework, "controls": rows}


@router.get("/queries")
async def auditor_queries(access: dict = Depends(auditor_access)) -> dict:
    _require_scope(access, "queries:read")
    async def _do():
        return await (await supabase._ensure()).table("auditor_queries").select("id,control_id,question,answer,status,asked_by,answered_at,created_at").eq("engagement_id", access["engagement_id"]).eq("tenant_id", access["tenant_id"]).order("created_at", desc=True).execute()
    return {"queries": list((await supabase._retry(_do, attempts=2)).data or [])}


@router.post("/queries", status_code=201)
async def create_auditor_query(body: QueryCreate, request: Request, access: dict = Depends(auditor_access)) -> dict:
    _require_scope(access, "queries:ask")
    if str(body.engagement_id) != str(access["engagement_id"]):
        raise HTTPException(403, "engagement mismatch")
    row = {"engagement_id": str(access["engagement_id"]), "tenant_id": access["tenant_id"], "control_id": str(body.control_id) if body.control_id else None, "question": body.question, "asked_by": "auditor"}
    async def _do():
        return await (await supabase._ensure()).table("auditor_queries").insert(row).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    return rows[0] if rows else {"created": False}


@router.post("/queries/{query_id}/answer")
async def answer_query(query_id: UUID, body: QueryAnswer, principal: DeveloperPrincipal = Depends(_org_principal)) -> dict:
    principal.require(("compliance:run",))
    async def _do():
        return await (await supabase._ensure()).table("auditor_queries").update({"answer": body.answer, "status": body.status, "answered_by": await _owner_user_id(principal), "answered_at": datetime.now(UTC).isoformat()}).eq("id", str(query_id)).eq("tenant_id", principal.tenant_id).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "query not found")
    return rows[0]


async def _owner_user_id(principal: DeveloperPrincipal) -> str | None:
    app = await supabase.select_one("developer_apps", "owner_user_id", id=principal.app_id)
    return str(app["owner_user_id"]) if app and app.get("owner_user_id") else None
