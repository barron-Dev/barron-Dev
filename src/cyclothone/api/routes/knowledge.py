from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.knowledge.hints import ContextHints
from cyclothone.knowledge.recommender import Recommender
from cyclothone.knowledge.search import KnowledgeSearch, KnowledgeUnavailable
from cyclothone.storage.supabase_client import supabase


router = APIRouter(prefix="/knowledge", tags=["knowledge"])
_search = KnowledgeSearch()
_hints = ContextHints()


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("knowledge:read",))
    return principal


def _manager(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("knowledge:manage",))
    return principal


@router.get("/search")
async def search(
    q: str = Query(min_length=1, max_length=300),
    limit: int = Query(default=30, ge=1, le=100),
) -> dict:
    try:
        return await _search.search(q, limit)
    except KnowledgeUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/hints")
async def hints(
    route: str = Query(min_length=1, max_length=500),
    audience: str = Query(default="client", pattern="^(visitor|client|partner|developer|admin)$"),
) -> dict:
    try:
        return await _hints.for_page(route, audience)
    except KnowledgeUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class RecContext(BaseModel):
    plan: str | None = Field(default=None, max_length=100)
    services_enabled: list[str] = Field(default_factory=list, max_length=200)
    partner: bool = False
    users: int = Field(default=0, ge=0, le=10_000_000)


class RecRequest(BaseModel):
    context: RecContext
    limit: int = Field(default=4, ge=1, le=20)


@router.post("/recommendations")
async def recommendations(
    body: RecRequest,
    principal: DeveloperPrincipal = Depends(_principal),
) -> list[dict]:
    try:
        return await Recommender(UUID(principal.tenant_id)).next_best(
            body.context.model_dump(), body.limit
        )
    except KnowledgeUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/guides")
async def list_guides(
    audience: str | None = Query(default=None, pattern="^(visitor|client|partner|developer|admin)$"),
    category: str | None = Query(default=None, max_length=120),
) -> list[dict]:
    async def _do():
        client = await supabase._ensure()
        query = (
            client.table("guides")
            .select(
                "id,slug,title,summary,audience,category,estimated_minutes,"
                "difficulty,tags,priority"
            )
            .eq("enabled", True)
            .order("priority")
            .order("slug")
            .limit(500)
        )
        if audience:
            query = query.eq("audience", audience)
        if category:
            query = query.eq("category", category)
        return await query.execute()

    try:
        return list((await supabase._retry(_do, attempts=2)).data or [])
    except Exception as exc:
        raise HTTPException(status_code=503, detail="guides unavailable") from exc


@router.get("/guides/{slug}")
async def get_guide(slug: str) -> dict:
    if len(slug) > 120:
        raise HTTPException(status_code=400, detail="invalid guide slug")

    async def _guide():
        client = await supabase._ensure()
        return await (
            client.table("guides")
            .select(
                "id,slug,title,summary,audience,category,estimated_minutes,"
                "difficulty,prerequisite_ids,tags,priority"
            )
            .eq("slug", slug)
            .eq("enabled", True)
            .limit(1)
            .execute()
        )

    try:
        guide_rows = (await supabase._retry(_guide, attempts=2)).data or []
        if not guide_rows:
            raise HTTPException(status_code=404, detail="guide not found")
        guide = guide_rows[0]

        async def _steps():
            client = await supabase._ensure()
            return await (
                client.table("guide_steps")
                .select(
                    "id,guide_id,step_no,title,body_md,action_url,action_label,"
                    "verify_kind,verify_payload"
                )
                .eq("guide_id", guide["id"])
                .order("step_no")
                .limit(500)
                .execute()
            )

        steps = (await supabase._retry(_steps, attempts=2)).data or []
        return {"guide": guide, "steps": steps}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="guide unavailable") from exc
