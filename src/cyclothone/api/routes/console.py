from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from sentinel.developer.auth import DeveloperPrincipal, authenticate_request
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/console", tags=["console"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


async def _count(table: str, tenant_id: str, since: datetime | None = None, until: datetime | None = None, **equals: str) -> int:
    async def _do():
        query = (await supabase._ensure()).table(table).select("id", count="exact", head=True).eq("tenant_id", tenant_id)
        for column, value in equals.items():
            query = query.eq(column, value)
        if since is not None:
            query = query.gte("created_at", since.isoformat())
        if until is not None:
            query = query.lt("created_at", until.isoformat())
        return await query.execute()

    result = await supabase._retry(_do, attempts=2)
    return int(result.count or 0)


async def _rows(table: str, tenant_id: str, columns: str, limit: int = 20) -> list[dict]:
    async def _do():
        return await (await supabase._ensure()).table(table).select(columns).eq("tenant_id", tenant_id).order("created_at", desc=True).limit(limit).execute()

    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.get("/overview")
async def overview(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    now = datetime.now(UTC)
    day = now - timedelta(hours=24)
    previous = day - timedelta(hours=24)

    agents = await _count("devices", principal.tenant_id)
    threats = await _count("detections", principal.tenant_id, day)
    previous_threats = await _count("detections", principal.tenant_id, previous, day)
    critical_cases = await _count("crime_cases", principal.tenant_id, day, severity="critical")
    feed = await _rows("detections", principal.tenant_id, "id,device_id,detector,score,verdict,reasons,created_at,mitre_technique", 12)

    return {
        "generated_at": now.isoformat(),
        "window": "24h",
        "agents": {"total": agents},
        "threats": {
            "last_24h": threats,
            "previous_24h": previous_threats,
            "delta_percent": round(((threats - previous_threats) / previous_threats) * 100, 1) if previous_threats else None,
        },
        "critical": {"count": critical_cases},
        "uptime_percent": None,
        "response_p95_ms": None,
        "coverage": {"endpoints": {"observed": agents}, "web_surface": None, "deep_web": None, "dark_web": None, "physical": None, "ai_agents": None},
        "feed": feed,
    }


@router.get("/threats")
async def threats(
    principal: DeveloperPrincipal = Depends(_principal),
    detector: str | None = Query(None, min_length=1, max_length=120),
    verdict: str | None = Query(None, min_length=1, max_length=40),
    mitre_technique: str | None = Query(None, min_length=1, max_length=40),
    device_id: UUID | None = Query(None),
    min_score: float | None = Query(None, ge=0, le=1),
    max_score: float | None = Query(None, ge=0, le=1),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    sort: str = Query("created_at", pattern="^(created_at|score|detector|verdict)$"),
    direction: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100000),
) -> dict:
    if min_score is not None and max_score is not None and min_score > max_score:
        raise HTTPException(422, {"error": "min_score_greater_than_max_score"})
    if since is not None and until is not None and since >= until:
        raise HTTPException(422, {"error": "since_must_precede_until"})

    columns = "id,tenant_id,device_id,event_id,detector,score,verdict,reasons,mitre_technique,created_at,processed_by_playbooks,processed_by_autocase"

    async def _do():
        query = (await supabase._ensure()).table("detections").select(columns, count="exact").eq("tenant_id", principal.tenant_id)
        if detector is not None:
            query = query.eq("detector", detector)
        if verdict is not None:
            query = query.eq("verdict", verdict)
        if mitre_technique is not None:
            query = query.eq("mitre_technique", mitre_technique)
        if device_id is not None:
            query = query.eq("device_id", str(device_id))
        if min_score is not None:
            query = query.gte("score", min_score)
        if max_score is not None:
            query = query.lte("score", max_score)
        if since is not None:
            query = query.gte("created_at", since.isoformat())
        if until is not None:
            query = query.lt("created_at", until.isoformat())
        return await query.order(sort, desc=direction == "desc").range(offset, offset + limit - 1).execute()

    result = await supabase._retry(_do, attempts=2)
    total = int(result.count or 0)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "items": list(result.data or []),
        "pagination": {"limit": limit, "offset": offset, "total": total, "has_more": offset + limit < total},
        "filters": {
            "detector": detector,
            "verdict": verdict,
            "mitre_technique": mitre_technique,
            "device_id": str(device_id) if device_id else None,
            "min_score": min_score,
            "max_score": max_score,
            "since": since.isoformat() if since else None,
            "until": until.isoformat() if until else None,
            "sort": sort,
            "direction": direction,
        },
    }


@router.get("/threats/{detection_id}")
async def threat_detail(detection_id: UUID, principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    async def _do():
        return await (await supabase._ensure()).table("detections").select(
            "id,tenant_id,device_id,event_id,detector,score,verdict,reasons,evidence,mitre_technique,created_at,processed_by_playbooks,processed_by_autocase"
        ).eq("id", str(detection_id)).eq("tenant_id", principal.tenant_id).maybe_single().execute()

    result = await supabase._retry(_do, attempts=2)
    if not result.data:
        raise HTTPException(404, {"error": "detection_not_found"})
    return dict(result.data)


@router.get("/devices")
async def devices(
    principal: DeveloperPrincipal = Depends(_principal),
    status: str | None = Query(None, min_length=1, max_length=40),
    platform: str | None = Query(None, min_length=1, max_length=80),
    search: str | None = Query(None, min_length=1, max_length=120),
    sort: str = Query("last_seen_at", pattern="^(last_seen_at|created_at|hostname|name|status)$"),
    direction: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100000),
) -> dict:
    columns = "id,hostname,name,os,os_version,arch,platform,platform_version,agent_version,last_seen_at,status,created_at,updated_at,cert_fingerprint"

    async def _do():
        query = (await supabase._ensure()).table("devices").select(columns, count="exact").eq("tenant_id", principal.tenant_id)
        if status is not None:
            query = query.eq("status", status)
        if platform is not None:
            query = query.eq("platform", platform)
        if search is not None:
            escaped = search.replace("%", "\\%").replace("_", "\\_")
            query = query.or_(f"hostname.ilike.%{escaped}%,name.ilike.%{escaped}%")
        return await query.order(sort, desc=direction == "desc").range(offset, offset + limit - 1).execute()

    result = await supabase._retry(_do, attempts=2)
    total = int(result.count or 0)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "items": list(result.data or []),
        "pagination": {"limit": limit, "offset": offset, "total": total, "has_more": offset + limit < total},
        "filters": {"status": status, "platform": platform, "search": search, "sort": sort, "direction": direction},
    }


@router.get("/devices/{device_id}")
async def device_detail(device_id: UUID, principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    async def _do():
        return await (await supabase._ensure()).table("devices").select(
            "id,tenant_id,hostname,name,os,os_version,arch,platform,platform_version,agent_version,last_seen_at,status,created_at,updated_at,cert_fingerprint,attestation"
        ).eq("id", str(device_id)).eq("tenant_id", principal.tenant_id).maybe_single().execute()

    result = await supabase._retry(_do, attempts=2)
    if not result.data:
        raise HTTPException(404, {"error": "device_not_found"})
    item = dict(result.data)
    item["attestation"] = item.get("attestation") or {}
    return item
