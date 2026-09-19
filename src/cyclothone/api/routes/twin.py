from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase
from cyclothone.twin.service import DigitalTwinService

router = APIRouter(prefix="/twin", tags=["digital-twin"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("twin:read",))
    return principal


def _manager(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("twin:manage",))
    return principal


class SimulateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    action: str = Field(
        pattern="^(isolate_host|kill_process|quarantine_file|disable_account|"
        "force_logout|block_hash|block_ip)$"
    )
    args: dict = Field(default_factory=dict)


@router.post("/simulate")
async def simulate(
    body: SimulateRequest,
    principal: DeveloperPrincipal = Depends(_manager),
) -> dict:
    try:
        return await DigitalTwinService(UUID(principal.tenant_id)).simulate(
            body.target, body.action, body.args
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/simulations")
async def list_simulations(
    limit: int = Query(50, ge=1, le=200),
    principal: DeveloperPrincipal = Depends(_principal),
) -> list[dict]:
    async def _do():
        client = await supabase._ensure()
        return await client.table("twin_simulations").select(
            "id,action,target_node_id,impact_score,cascade_size,"
            "recommendation,duration_ms,created_at"
        ).eq("tenant_id", principal.tenant_id).order(
            "created_at", desc=True
        ).limit(limit).execute()

    return list((await supabase._retry(_do)).data or [])


@router.get("/nodes")
async def list_nodes(
    node_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(500, ge=1, le=5000),
    principal: DeveloperPrincipal = Depends(_principal),
) -> list[dict]:
    async def _do():
        client = await supabase._ensure()
        query = client.table("twin_nodes").select(
            "id,node_type,external_id,label,criticality,last_seen"
        ).eq("tenant_id", principal.tenant_id).order(
            "criticality", desc=True
        ).limit(limit)
        if node_type:
            query = query.eq("node_type", node_type)
        return await query.execute()

    return list((await supabase._retry(_do)).data or [])


@router.get("/stats")
async def stats(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    data = await supabase.rpc("twin_stats", {"p_tenant": principal.tenant_id})
    if not isinstance(data, dict):
        raise HTTPException(502, "digital twin stats unavailable")
    return data
