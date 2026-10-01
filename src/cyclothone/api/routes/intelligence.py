from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/intelligence", tags=["threat-intelligence"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/feeds")
async def feeds(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    result = await supabase.select("intel_feeds", "id,tenant_id,name,kind,endpoint,enabled,last_pull_at,last_status,created_at", tenant_id=principal.tenant_id)
    return {"items": result, "total": len(result)}


@router.get("/indicators")
async def indicators(principal: DeveloperPrincipal = Depends(_principal), ioc_type: str | None = Query(None, min_length=1, max_length=80), severity: str | None = Query(None, min_length=1, max_length=40), limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)) -> dict:
    client = await supabase._ensure()
    query = client.table("indicators").select("id,tenant_id,ioc_type,value,severity,confidence,source,tags,context,first_seen,last_seen,expires_at", count="exact").or_(f"tenant_id.eq.{principal.tenant_id},tenant_id.is.null")
    if ioc_type is not None:
        query = query.eq("ioc_type", ioc_type)
    if severity is not None:
        query = query.eq("severity", severity)
    result = await supabase._retry(lambda: query.order("last_seen", desc=True).range(offset, offset + limit - 1).execute(), attempts=2)
    total = int(result.count or 0)
    return {"items": list(result.data or []), "pagination": {"limit": limit, "offset": offset, "total": total, "has_more": offset + limit < total}}


@router.get("/pulls")
async def pulls(principal: DeveloperPrincipal = Depends(_principal), limit: int = Query(50, ge=1, le=200)) -> dict:
    feeds_result = await supabase.select("intel_feeds", "id", tenant_id=principal.tenant_id)
    feed_ids = [str(row["id"]) for row in feeds_result]
    if not feed_ids:
        return {"items": [], "total": 0}
    client = await supabase._ensure()
    result = await supabase._retry(lambda: client.table("intel_pull_log").select("id,feed_id,status,indicators_added,indicators_updated,duration_ms,error,ts").in_("feed_id", feed_ids).order("ts", desc=True).limit(limit).execute(), attempts=2)
    return {"items": list(result.data or []), "total": len(result.data or [])}
