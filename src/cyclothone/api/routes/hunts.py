from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.hunting.executor import QueryExecutor
from cyclothone.hunting.parser import parse
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/hunts", tags=["hunting"])
_executor = QueryExecutor()


async def _owner_user_id(principal: DeveloperPrincipal) -> str | None:
    app = await supabase.select_one("developer_apps", "owner_user_id", id=principal.app_id)
    return str(app["owner_user_id"]) if app and app.get("owner_user_id") else None


class QueryRequest(BaseModel):
    query: str = Field(min_length=4, max_length=8000)


@router.post("/run")
async def run_query(body: QueryRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("hunting:run",))
    try:
        parse(body.query)
        rows, elapsed = await _executor.run(UUID(principal.tenant_id), body.query)
    except SyntaxError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"syntax: {exc}") from exc

    await _record_run(UUID(principal.tenant_id), None, body.query, len(rows), elapsed, "success", principal)
    return {"rows": rows, "count": len(rows), "duration_ms": elapsed}


class HuntCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    query: str = Field(min_length=4, max_length=8000)
    params: dict[str, object] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=32)
    is_template: bool = False
    is_public: bool = False


@router.post("/", status_code=201)
async def create_hunt(body: HuntCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("hunting:write",))
    try:
        parse(body.query)
    except SyntaxError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"syntax: {exc}") from exc
    row = {
        "tenant_id": principal.tenant_id, "name": body.name, "description": body.description,
        "query": body.query, "params": body.params, "tags": body.tags,
        "is_template": body.is_template, "is_public": body.is_public,
        "created_by": await _owner_user_id(principal),
    }
    async def _do():
        return await (await supabase._ensure()).table("hunts").insert(row).execute()
    response = await supabase._retry(_do)
    return (response.data or [{}])[0]


@router.get("/")
async def list_hunts(tag: str | None = None, principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("hunting:read",))
    async def _do():
        q = (await supabase._ensure()).table("hunts").select(
            "id,name,description,query,params,tags,is_template,is_public,run_count,last_run_at,created_at,updated_at"
        ).eq("tenant_id", principal.tenant_id)
        if tag:
            q = q.contains("tags", [tag])
        return await q.order("updated_at", desc=True).execute()
    response = await supabase._retry(_do)
    return list(response.data or [])


@router.get("/runs/history")
async def run_history(
    hunt_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict]:
    principal.require(("hunting:read",))
    async def _do():
        q = (await supabase._ensure()).table("hunt_runs").select(
            "id,hunt_id,status,rows_returned,duration_ms,triggered_by,started_at,ended_at,error"
        ).eq("tenant_id", principal.tenant_id)
        if hunt_id:
            q = q.eq("hunt_id", str(hunt_id))
        return await q.order("started_at", desc=True).limit(limit).execute()
    response = await supabase._retry(_do)
    return list(response.data or [])


@router.get("/{hunt_id}")
async def get_hunt(hunt_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("hunting:read",))
    async def _do():
        return await (await supabase._ensure()).table("hunts").select("*").eq(
            "id", str(hunt_id)
        ).eq("tenant_id", principal.tenant_id).limit(1).execute()
    response = await supabase._retry(_do)
    if not response.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "hunt not found")
    return response.data[0]


class HuntUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    query: str | None = Field(default=None, min_length=4, max_length=8000)
    params: dict[str, object] | None = None
    tags: list[str] | None = Field(default=None, max_length=32)


@router.patch("/{hunt_id}")
async def update_hunt(hunt_id: UUID, body: HuntUpdate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("hunting:write",))
    patch = body.model_dump(exclude_unset=True)
    if "query" in patch:
        try:
            parse(patch["query"])
        except SyntaxError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"syntax: {exc}") from exc
    async def _do():
        return await (await supabase._ensure()).table("hunts").update(patch).eq(
            "id", str(hunt_id)
        ).eq("tenant_id", principal.tenant_id).execute()
    response = await supabase._retry(_do)
    if not response.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "hunt not found")
    return response.data[0]


@router.delete("/{hunt_id}", status_code=204)
async def delete_hunt(hunt_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> None:
    principal.require(("hunting:write",))
    async def _do():
        return await (await supabase._ensure()).table("hunts").delete().eq(
            "id", str(hunt_id)
        ).eq("tenant_id", principal.tenant_id).execute()
    await supabase._retry(_do)


@router.post("/{hunt_id}/run")
async def run_saved_hunt(hunt_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("hunting:run",))
    hunt = await get_hunt(hunt_id, principal)
    try:
        rows, elapsed = await _executor.run(UUID(principal.tenant_id), hunt["query"])
    except SyntaxError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"syntax: {exc}") from exc
    await _record_run(UUID(principal.tenant_id), hunt_id, hunt["query"], len(rows), elapsed, "success", principal)
    return {"rows": rows, "count": len(rows), "duration_ms": elapsed}


async def _record_run(tenant_id: UUID, hunt_id: UUID | None, query: str, rows: int, elapsed: int, state: str, principal: DeveloperPrincipal) -> None:
    async def _do():
        return await (await supabase._ensure()).table("hunt_runs").insert({
            "tenant_id": str(tenant_id), "hunt_id": str(hunt_id) if hunt_id else None,
            "query": query, "status": state, "rows_returned": rows, "duration_ms": elapsed,
            "triggered_by": "user", "ran_by": await _owner_user_id(principal),
            "ended_at": datetime.now(UTC).isoformat(),
        }).execute()
    try:
        await supabase._retry(_do, attempts=1)
    except Exception:
        # Query execution remains successful; telemetry failure must not alter results.
        pass
