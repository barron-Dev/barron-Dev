from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cyclothone.api.routes.darkweb import _require
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.identity_investigation import build_integration_matrix, build_report, normalize_target
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/identity", tags=["identity-investigation"])


class InvestigateRequest(BaseModel):
    query_type: Literal["domain", "email", "username", "company_name", "phone", "ip", "wallet", "executive_name", "api_key_hash", "employee_id", "customer_id"]
    query_value: str = Field(min_length=2, max_length=512)
    modules: list[str] = Field(default_factory=lambda: ["all"], max_length=5)


def _validate_modules(modules: list[str]) -> list[str]:
    allowed = {"all", "darkweb", "breach", "code", "infra", "social"}
    requested = sorted(set(modules or ["all"]))
    if not requested or set(requested) - allowed or ("all" in requested and len(requested) > 1):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported investigation module selection")
    return requested


@router.post("/investigate")
async def investigate(body: InvestigateRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:read")
    try:
        target = normalize_target(body.query_type, body.query_value)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    requested_modules = _validate_modules(body.modules)

    # Only investigate identifiers already approved in this tenant's watchlist.
    async def _watch():
        return await (await supabase._ensure()).table("dw_watchlist").select(
            "id,kind,value,tenant_id"
        ).eq("tenant_id", str(tenant_id)).eq("kind", body.query_type).limit(1000).execute()

    async def _sources():
        return await (await supabase._ensure()).table("dw_sources").select(
            "id,name,kind,enabled,last_pull_at,last_status,web_layer,access_mode"
        ).execute()

    try:
        watch_result, source_result = await asyncio.gather(
            supabase._retry(_watch, attempts=1),
            supabase._retry(_sources, attempts=1),
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "identity investigation data unavailable") from exc

    watches = watch_result.data or []
    matching = []
    for row in watches:
        try:
            if normalize_target(str(row.get("kind") or ""), str(row.get("value") or "")) == target:
                matching.append(row)
        except ValueError:
            continue
    if not matching:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "target must first exist in this tenant's authorized dark-web watchlist",
        )

    watch_ids = sorted({str(row["id"]) for row in matching})
    async def _findings_for(watch_id: str):
        async def _query():
            return await (await supabase._ensure()).table("dw_findings").select(
                "id,source_id,content_hash,kind,matched_value,context,source_url,severity,first_seen,tenant_id,watchlist_id,web_layer,access_mode,collected_at"
            ).eq("watchlist_id", watch_id).eq("tenant_id", str(tenant_id)).order(
                "first_seen", desc=True
            ).limit(500).execute()
        return await supabase._retry(_query, attempts=1)

    try:
        results = await asyncio.gather(*[_findings_for(watch_id) for watch_id in watch_ids])
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "persisted evidence lookup failed") from exc

    findings = [row for result in results for row in (result.data or [])]
    sources = source_result.data or []
    return build_report(
        target_kind=body.query_type,
        canonical_target=target,
        watch_id=",".join(watch_ids),
        findings=findings,
        sources=sources,
        requested_modules=requested_modules,
    )


@router.get("/integration-matrix")
async def integration_matrix(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    _require(principal, "darkweb:read")

    async def _do():
        return await (await supabase._ensure()).table("dw_sources").select(
            "id,name,kind,enabled,last_pull_at,last_status,web_layer,access_mode"
        ).execute()

    try:
        result = await supabase._retry(_do, attempts=1)
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "integration status unavailable") from exc
    sources = result.data or []
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_count": len(sources),
        "integration_matrix": build_integration_matrix(sources, evidence_count=0),
        "note": "Statuses are derived from persisted source configuration and last-pull metadata. Unknown stages are not treated as successful.",
    }
