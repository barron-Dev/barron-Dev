from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.protection.regional_correlation import regional_temporal_intersection
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/vip-protection", tags=["controlled-protective-intelligence"])
MAX_ASSIGNMENT_DAYS = 14
CORRELATION_WINDOW = timedelta(hours=48)


def _actor(principal: DeveloperPrincipal) -> str:
    if not principal.user_id:
        raise HTTPException(403, {"error": "human_operator_identity_required"})
    return f"user:{principal.user_id}"


def _require(principal: DeveloperPrincipal, scope: str) -> DeveloperPrincipal:
    principal.require((scope,))
    return principal


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


class AssignmentCreate(BaseModel):
    assignment_name: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=8, max_length=500)
    region_code: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]{1,31}$")

    @field_validator("region_code", mode="before")
    @classmethod
    def normalize_region(cls, value: str) -> str:
        return value.strip().upper() if isinstance(value, str) else value
    subject_ref: str = Field(min_length=8, max_length=256)
    authorization_ref: str = Field(min_length=8, max_length=256)
    consent_evidence_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    start_time: datetime
    end_time: datetime

    @field_validator("start_time", "end_time")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        return _utc(value)


class CorrelateRequest(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=200)


class SosRequest(BaseModel):
    confirm: bool = True


def _safe_assignment(row: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "id", "tenant_id", "assignment_name", "purpose", "region_code",
        "start_time", "end_time", "status", "approved_at", "closed_at",
        "expired_at", "created_at",
    )
    return {key: row.get(key) for key in allowed}


async def _get_assignment(assignment_id: UUID, tenant_id: str) -> dict[str, Any]:
    row = await supabase.select_one(
        "vip_assignments",
        "id,tenant_id,assignment_name,purpose,region_code,start_time,end_time,status,approved_at,closed_at,expired_at,created_at",
        id=str(assignment_id),
        tenant_id=tenant_id,
    )
    if not row:
        raise HTTPException(404, {"error": "assignment_not_found"})
    return row


@router.post("/assignments", status_code=201)
async def create_assignment(
    body: AssignmentCreate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:manage")
    if body.end_time <= body.start_time or body.end_time - body.start_time > timedelta(days=MAX_ASSIGNMENT_DAYS):
        raise HTTPException(422, {"error": "assignment_window_must_be_1_to_14_days"})
    try:
        row = await supabase.rpc("vip_create_assignment", {
            "p_tenant_id": principal.tenant_id,
            "p_actor": _actor(principal),
            "p_subject_ref": body.subject_ref,
            "p_assignment_name": body.assignment_name.strip(),
            "p_purpose": body.purpose.strip(),
            "p_region_code": body.region_code.strip().upper(),
            "p_start_time": body.start_time.isoformat(),
            "p_end_time": body.end_time.isoformat(),
            "p_authorization_ref": body.authorization_ref,
            "p_consent_evidence_sha256": body.consent_evidence_sha256.lower(),
        })
    except Exception as exc:
        raise HTTPException(409, {"error": "assignment_creation_rejected", "detail": str(exc)[:200]}) from exc
    return {"assignment": _safe_assignment(row), "approval_required": True,
            "location_collection": False, "maximum_duration_days": MAX_ASSIGNMENT_DAYS}


@router.post("/assignments/{assignment_id}/approve")
async def approve_assignment(
    assignment_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:approve")
    try:
        row = await supabase.rpc("vip_approve_assignment", {
            "p_tenant_id": principal.tenant_id,
            "p_assignment_id": str(assignment_id),
            "p_actor": _actor(principal),
        })
    except Exception as exc:
        raise HTTPException(409, {"error": "approval_rejected", "detail": str(exc)[:200]}) from exc
    return {"assignment": _safe_assignment(row), "separation_of_duties": True}


@router.get("/assignments")
async def list_assignments(
    limit: int = Query(100, ge=1, le=250),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:read")
    client = await supabase._ensure()
    response = await (
        client.table("vip_assignments")
        .select("id,tenant_id,assignment_name,purpose,region_code,start_time,end_time,status,created_by,approved_by,approved_at,closed_at,expired_at,created_at")
        .eq("tenant_id", principal.tenant_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return {"items": list(response.data or [])}


@router.post("/assignments/{assignment_id}/correlate")
async def correlate_public_threats(
    assignment_id: UUID,
    body: CorrelateRequest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:correlate")
    assignment = await _get_assignment(assignment_id, principal.tenant_id)
    start = _utc(datetime.fromisoformat(str(assignment["start_time"]).replace("Z", "+00:00")))
    end = _utc(datetime.fromisoformat(str(assignment["end_time"]).replace("Z", "+00:00")))
    now = datetime.now(timezone.utc)
    if assignment["status"] != "active" or not (start <= now < end):
        raise HTTPException(409, {"error": "assignment_not_active"})
    client = await supabase._ensure()
    findings_response = await (
        client.table("dw_findings")
        .select("id,tenant_id,source_metadata,first_seen,content_hash,source_id")
        .eq("tenant_id", principal.tenant_id)
        .in_("id", body.finding_ids)
        .limit(200)
        .execute()
    )
    matches: list[dict[str, Any]] = []
    skipped = 0
    for finding in findings_response.data or []:
        metadata = finding.get("source_metadata") or {}
        if not isinstance(metadata, dict):
            skipped += 1
            continue
        region = metadata.get("region_code")
        observed = metadata.get("observed_at")
        source_type = metadata.get("source_type")
        evidence_hash = str(finding.get("content_hash") or "").lower()
        if (
            not isinstance(region, str)
            or region != assignment["region_code"]
            or source_type not in {"public_event", "authorized_socmint", "adsb_flight"}
            or not isinstance(observed, str)
            or len(evidence_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in evidence_hash)
        ):
            skipped += 1
            continue
        try:
            event_at = _utc(datetime.fromisoformat(observed.replace("Z", "+00:00")))
        except ValueError:
            skipped += 1
            continue
        intersects, delta = regional_temporal_intersection(
            assignment["region_code"], start, end, region, event_at,
            window=CORRELATION_WINDOW,
        )
        if not intersects or delta is None:
            continue
        record = {
            "tenant_id": principal.tenant_id,
            "assignment_id": str(assignment_id),
            "threat_finding_id": int(finding["id"]),
            "region_code": region,
            "time_delta_seconds": delta,
            "threat_evidence_sha256": evidence_hash,
        }
        try:
            await client.table("vip_region_threat_matches").insert(record).execute()
        except Exception:
            existing = await (
                client.table("vip_region_threat_matches").select("id")
                .eq("assignment_id", str(assignment_id))
                .eq("threat_finding_id", int(finding["id"]))
                .limit(1).execute()
            )
            if not existing.data:
                raise
            continue
        await client.table("vip_assignment_events").insert({
            "tenant_id": principal.tenant_id,
            "assignment_id": str(assignment_id),
            "event_type": "region_match_recorded",
            "actor": _actor(principal),
            "metadata": {"match_recorded": True, "intent_inference": False},
        }).execute()
        matches.append({
            "finding_id": int(finding["id"]),
            "region_code": region,
            "time_delta_seconds": delta,
            "evidence_sha256": evidence_hash,
            "interpretation": "public_region_and_time_intersection_only",
        })
    return {
        "assignment_id": str(assignment_id),
        "matches": matches,
        "match_count": len(matches),
        "unqualified_or_unlocated_findings": skipped,
        "time_window_hours": 48,
        "precise_personal_location_used": False,
        "intent_inference": False,
        "confidence": "not_assigned",
    }


@router.post("/assignments/{assignment_id}/sos", status_code=201)
async def raise_sos(
    assignment_id: UUID,
    body: SosRequest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:sos")
    if not body.confirm:
        raise HTTPException(422, {"error": "sos_confirmation_required"})
    try:
        incident = await supabase.rpc("vip_raise_sos", {
            "p_tenant_id": principal.tenant_id,
            "p_assignment_id": str(assignment_id),
            "p_actor": _actor(principal),
        })
    except Exception as exc:
        raise HTTPException(409, {"error": "sos_rejected", "detail": str(exc)[:200]}) from exc
    return {"incident": incident, "priority": "P1", "dispatch_status": "not_dispatched",
            "human_response_required": True, "physical_controls_changed": False}


@router.post("/assignments/{assignment_id}/close")
async def close_assignment(
    assignment_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:manage")
    try:
        await supabase.rpc("vip_close_assignment", {
            "p_tenant_id": principal.tenant_id,
            "p_assignment_id": str(assignment_id),
            "p_actor": _actor(principal),
        })
    except Exception as exc:
        raise HTTPException(409, {"error": "close_rejected", "detail": str(exc)[:200]}) from exc
    row = await _get_assignment(assignment_id, principal.tenant_id)
    return {"assignment": row, "regional_matches": "purged_synchronously",
            "personal_fields": "redacted"}


@router.get("/assignments/{assignment_id}/incidents")
async def list_incidents(
    assignment_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "vip:read")
    await _get_assignment(assignment_id, principal.tenant_id)
    client = await supabase._ensure()
    response = await (
        client.table("vip_protection_incidents")
        .select("id,incident_type,priority,status,dispatch_status,summary,raised_by,acknowledged_by,acknowledged_at,created_at")
        .eq("tenant_id", principal.tenant_id)
        .eq("assignment_id", str(assignment_id))
        .order("created_at", desc=True)
        .limit(100)
        .execute()
    )
    return {"items": list(response.data or [])}
