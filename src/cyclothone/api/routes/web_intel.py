from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase
from cyclothone.web.orchestrator import WebIntelligenceOrchestrator

router = APIRouter(prefix="/web-intel", tags=["web-intelligence"])
_orchestrator = WebIntelligenceOrchestrator()
LAYERS = {"surface", "deep", "dark"}
ENGINES = {"google", "bing", "duckduckgo", "yandex"}


def tenant(principal: DeveloperPrincipal, scope: str) -> str:
    principal.require((scope,))
    return principal.tenant_id


class TargetCreate(BaseModel):
    layer: str = Field(pattern="^(surface|deep|dark)$")
    kind: str = Field(pattern="^(domain|paste_site|forum|marketplace|onion_service|search_engine|api|rss)$")
    url: str = Field(min_length=8, max_length=2048)
    auth_ref: str | None = Field(default=None, max_length=512)
    crawl_interval: int = Field(default=3600, ge=60, le=604800)
    max_depth: int = Field(default=0, ge=0, le=3)
    respect_robots: bool = True


@router.get("/targets")
async def list_targets(layer: str | None = None, principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tid = tenant(principal, "web:read")
    if layer and layer not in LAYERS:
        raise HTTPException(400, "invalid layer")
    async def _do():
        q = (await supabase._ensure()).table("web_crawl_targets").select("id,tenant_id,layer,kind,url,crawl_interval,max_depth,respect_robots,enabled,last_crawl_at,last_status,created_at").or_(f"tenant_id.eq.{tid},tenant_id.is.null")
        if layer: q = q.eq("layer", layer)
        return await q.order("created_at", desc=True).limit(1000).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/targets", status_code=status.HTTP_201_CREATED)
async def add_target(body: TargetCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tid = tenant(principal, "web:manage")
    from cyclothone.web.crawler import WebCrawler
    try:
        WebCrawler._validate_target(body.url, body.layer)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if body.layer == "dark" and not body.url.lower().split("://", 1)[-1].split("/", 1)[0].endswith(".onion"):
        raise HTTPException(400, "dark targets require an onion hostname")
    row = {**body.model_dump(), "tenant_id": tid}
    async def _do(): return await (await supabase._ensure()).table("web_crawl_targets").insert(row).execute()
    data = (await supabase._retry(_do, attempts=2)).data or []
    if not data: raise HTTPException(502, "target persistence failed")
    return data[0]


@router.delete("/targets/{target_id}", status_code=204)
async def delete_target(target_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> None:
    tid = tenant(principal, "web:manage")
    async def _do(): return await (await supabase._ensure()).table("web_crawl_targets").delete().eq("id", str(target_id)).eq("tenant_id", tid).execute()
    await supabase._retry(_do, attempts=2)


@router.get("/pages")
async def list_pages(target_id: UUID | None = None, limit: int = Query(200, ge=1, le=1000), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tid = tenant(principal, "web:read")
    async def _do():
        q = (await supabase._ensure()).table("web_crawl_pages").select("id,target_id,url,status_code,content_type,matched_terms,emails_found,urls_found,wallets_found,credentials_found,severity,first_seen").eq("tenant_id", tid)
        if target_id: q = q.eq("target_id", str(target_id))
        return await q.order("first_seen", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


class DorkCreate(BaseModel):
    engine: str = Field(pattern="^(google|bing|duckduckgo|yandex)$")
    query: str = Field(min_length=1, max_length=500)
    category: str = Field(min_length=1, max_length=64)


@router.get("/dorks")
async def list_dorks(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tid = tenant(principal, "web:read")
    async def _do(): return await (await supabase._ensure()).table("search_dorks").select("id,engine,query,category,enabled,last_run_at,created_at").eq("tenant_id", tid).order("created_at", desc=True).limit(500).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/dorks", status_code=status.HTTP_201_CREATED)
async def add_dork(body: DorkCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tid = tenant(principal, "web:manage")
    row = {**body.model_dump(), "tenant_id": tid}
    async def _do(): return await (await supabase._ensure()).table("search_dorks").insert(row).execute()
    data = (await supabase._retry(_do, attempts=2)).data or []
    if not data: raise HTTPException(502, "dork persistence failed")
    return data[0]


@router.post("/crawl", status_code=202)
async def run_crawl(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant(principal, "web:manage")
    # Scheduler owns recurring work; this endpoint is intentionally a bounded
    # operator trigger rather than a background process spawned per request.
    return {"accepted": True, "message": "configured targets are processed by the web-intelligence scheduler"}
