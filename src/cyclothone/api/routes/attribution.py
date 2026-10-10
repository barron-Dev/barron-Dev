from __future__ import annotations

import os
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.attribution.alerts import _public_https_url
from cyclothone.attribution.graph import detect_communities
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/attribution", tags=["darkweb-attribution"])
TI_READ, TI_REVIEW, TI_MANAGE = "threat-intel:read", "threat-intel:review", "threat-intel:manage"


def _tenant(principal: DeveloperPrincipal, scope: str) -> UUID:
    principal.require((scope,))
    try:
        return UUID(principal.tenant_id)
    except ValueError as exc:
        raise HTTPException(403, "tenant context invalid") from exc


def _fernet() -> Fernet:
    key = (os.getenv("CYCLOTHONE_WEBHOOK_ENCRYPTION_KEY") or "").strip()
    if not key:
        raise HTTPException(503, "webhook encryption is not configured")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise HTTPException(503, "webhook encryption key is invalid") from exc


def _endpoint(value: str) -> str:
    try:
        safe = _public_https_url(value)
    except ValueError as exc:
        raise HTTPException(400, "endpoint must be public HTTPS and its hostname must be allowlisted") from exc
    if urlsplit(safe).hostname is None:
        raise HTTPException(400, "invalid webhook endpoint")
    return safe


class ReviewBody(BaseModel):
    verdict: str = Field(pattern="^(accepted|rejected|needs_more_evidence)$")
    notes: str | None = Field(default=None, max_length=4000)


class WebhookCreate(BaseModel):
    endpoint_url: str = Field(min_length=12, max_length=2048)
    secret: str = Field(min_length=32, max_length=512)
    event_types: list[str] = Field(default_factory=lambda: ["PROVISIONAL_ACTOR_CREATED", "ATTRIBUTION_TIER_CHANGED", "PROFILE_CHANGED"], max_length=3)


ALLOWED_EVENTS = {"PROVISIONAL_ACTOR_CREATED", "ATTRIBUTION_TIER_CHANGED", "PROFILE_CHANGED"}


@router.get("/actors")
async def list_actor_profiles(limit: int = Query(default=100, ge=1, le=500), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = str(_tenant(principal, TI_READ))
    async def _do():
        return await (await supabase._ensure()).table("dw_actor_profiles").select(
            "actor_id,tenant_id,primary_name,actor_type,aliases,attributed_to,attribution_confidence,first_seen,last_activity,source_count,analyst_review_required,provisional,profile_version,review_status,profile"
        ).order("last_activity", desc=True).limit(min(2000, limit * 4)).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    result = []
    for row in rows:
        if row.get("tenant_id") not in (None, tenant_id):
            continue
        profile = row.get("profile") or {}
        result.append({
            **{k: row.get(k) for k in ("actor_id","primary_name","actor_type","aliases","attributed_to","attribution_confidence","first_seen","last_activity","source_count","analyst_review_required","provisional","profile_version","review_status")},
            "tenant_owned": row.get("tenant_id") == tenant_id,
            "diamond_model": profile.get("diamond_model") or {},
            "attack_techniques": profile.get("attack_techniques") or [],
            "malware_families": profile.get("malware_families") or [],
            "target_sectors": profile.get("target_sectors") or [],
            "target_regions": profile.get("target_regions") or [],
            "infrastructure": profile.get("infrastructure") or {},
        })
        if len(result) >= limit:
            break
    return result


@router.get("/actors/{actor_id}/relationships")
async def actor_relationships(actor_id: str, principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = str(_tenant(principal, TI_READ))
    if not actor_id or len(actor_id) > 128:
        raise HTTPException(400, "invalid actor id")
    client = await supabase._ensure()
    left = await client.table("dw_actor_relationships").select(
        "relationship_id,source_actor_id,target_actor_id,relationship_type,confidence,evidence_ids,analyst_review_required,updated_at"
    ).eq("tenant_id", tenant_id).eq("source_actor_id", actor_id).limit(500).execute()
    right = await client.table("dw_actor_relationships").select(
        "relationship_id,source_actor_id,target_actor_id,relationship_type,confidence,evidence_ids,analyst_review_required,updated_at"
    ).eq("tenant_id", tenant_id).eq("target_actor_id", actor_id).limit(500).execute()
    unique = {str(row["relationship_id"]): row for row in [*(left.data or []), *(right.data or [])]}
    return list(unique.values())


@router.get("/assessments")
async def list_assessments(
    limit: int = Query(default=100, ge=1, le=500),
    tier: str | None = Query(default=None, pattern="^(CONFIRMED|SUSPECTED|POSSIBLE|INSUFFICIENT)$"),
    review_status: str | None = Query(default=None, pattern="^(pending|accepted|rejected|needs_more_evidence)$"),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict]:
    tenant_id = str(_tenant(principal, TI_READ))
    async def _do():
        q = (await supabase._ensure()).table("dw_attribution_assessments").select(
            "assessment_id,activity_cluster_id,actor_id,score,tier,raw_score_tier,signals,explanation,diamond_model,attack_techniques,kill_chain_phases,source_evidence_ids,independent_source_count,analyst_review_required,review_status,reviewed_at,review_notes,created_at"
        ).eq("tenant_id", tenant_id)
        if tier: q = q.eq("tier", tier)
        if review_status: q = q.eq("review_status", review_status)
        return await q.order("created_at", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/assessments/{assessment_id}/review")
async def review_assessment(assessment_id: UUID, body: ReviewBody, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = str(_tenant(principal, TI_REVIEW))
    if not principal.user_id:
        raise HTTPException(403, "a user identity is required for analyst review")
    now = datetime.now(UTC).isoformat()
    async def _do():
        return await (await supabase._ensure()).table("dw_attribution_assessments").update({
            "review_status": body.verdict, "reviewed_by": principal.user_id, "reviewed_at": now,
            "review_notes": body.notes, "analyst_review_required": body.verdict != "accepted",
        }).eq("assessment_id", str(assessment_id)).eq("tenant_id", tenant_id).select(
            "assessment_id,activity_cluster_id,actor_id,score,tier,review_status,reviewed_at,review_notes"
        ).limit(1).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "assessment not found")
    actor_id = rows[0].get("actor_id")
    if actor_id:
        await (await supabase._ensure()).table("dw_actor_profiles").update({
            "review_status": body.verdict, "analyst_review_required": body.verdict != "accepted",
            "attribution_confidence": rows[0]["tier"] if body.verdict == "accepted" else ("INSUFFICIENT" if body.verdict == "rejected" else rows[0]["tier"]),
            "updated_at": now,
        }).eq("actor_id", actor_id).eq("tenant_id", tenant_id).execute()
    return rows[0]


@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
async def enqueue_attribution_job(watchlist_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = str(_tenant(principal, TI_MANAGE))
    try:
        job_id = await supabase.rpc("enqueue_dw_attribution_job", {"p_tenant_id": tenant_id, "p_watchlist_id": str(watchlist_id)})
    except Exception as exc:
        raise HTTPException(502, "attribution job could not be queued") from exc
    return {"job_id": str(job_id), "status": "queued"}


@router.get("/communities")
async def actor_communities(limit: int = Query(default=500, ge=1, le=2000), principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = str(_tenant(principal, TI_READ))
    async def _do():
        return await (await supabase._ensure()).table("dw_actor_profiles").select(
            "actor_id,primary_name,tenant_id,profile,attack_techniques"
        ).limit(limit).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    return detect_communities([r for r in rows if r.get("tenant_id") in (None, tenant_id)])


@router.get("/techniques/{technique_id}")
async def get_attack_technique(technique_id: str, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    _tenant(principal, TI_READ)
    if len(technique_id) > 12 or not technique_id.startswith("T"):
        raise HTTPException(400, "invalid ATT&CK technique id")
    async def _do():
        return await (await supabase._ensure()).table("dw_attack_techniques").select(
            "technique_id,name,description,platforms,tactics,url,updated_at"
        ).eq("technique_id", technique_id.upper()).limit(1).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "technique not present in the synchronized ATT&CK catalogue")
    return rows[0]


@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(body: WebhookCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = str(_tenant(principal, TI_MANAGE))
    if not principal.user_id:
        raise HTTPException(403, "a user identity is required to register a webhook")
    events = sorted(set(body.event_types))
    if not events or not set(events).issubset(ALLOWED_EVENTS):
        raise HTTPException(400, "unsupported event type")
    endpoint = _endpoint(body.endpoint_url)
    ciphertext = _fernet().encrypt(body.secret.encode()).decode()
    row = {"tenant_id": tenant_id, "endpoint_url": endpoint, "secret_ciphertext": ciphertext, "event_types": events, "created_by": principal.user_id, "enabled": True}
    async def _do():
        return await (await supabase._ensure()).table("dw_attribution_webhooks").insert(row).execute()
    try:
        data = (await supabase._retry(_do, attempts=2)).data or []
    except Exception as exc:
        raise HTTPException(502, "webhook registration failed") from exc
    saved = data[0] if data else {}
    return {"webhook_id": saved.get("webhook_id"), "endpoint_host": urlsplit(endpoint).hostname, "event_types": events, "enabled": True}


@router.get("/webhooks")
async def list_webhooks(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = str(_tenant(principal, TI_MANAGE))
    async def _do():
        return await (await supabase._ensure()).table("dw_attribution_webhooks").select(
            "webhook_id,endpoint_url,event_types,enabled,created_at,last_delivery_at"
        ).eq("tenant_id", tenant_id).order("created_at", desc=True).limit(200).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disable_webhook(webhook_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> None:
    tenant_id = str(_tenant(principal, TI_MANAGE))
    async def _do():
        return await (await supabase._ensure()).table("dw_attribution_webhooks").update({"enabled": False}).eq("webhook_id", str(webhook_id)).eq("tenant_id", tenant_id).execute()
    await supabase._retry(_do, attempts=2)
