from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from sentinel.compliance.service import ComplianceError, ComplianceService, FRAMEWORKS
from sentinel.developer.auth import DeveloperPrincipal, authenticate_request

router = APIRouter(prefix="/compliance", tags=["compliance"])
_service = ComplianceService()


class ComplianceRunRequest(BaseModel):
    framework: str = Field(pattern="^(soc2|iso27001|gdpr|hipaa)$")
    period_start: datetime
    period_end: datetime


@router.get("/frameworks")
async def frameworks(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    return await _service.list_frameworks(UUID(principal.tenant_id))


@router.post("/runs", status_code=status.HTTP_201_CREATED)
async def run_compliance(
    body: ComplianceRunRequest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict:
    principal.require(("compliance:run",))
    try:
        return await _service.collect(
            UUID(principal.tenant_id),
            body.framework,
            body.period_start,
            body.period_end,
            await _owner_user_id(principal),
        )
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/runs/last-24h", status_code=status.HTTP_201_CREATED)
async def run_last_24h(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:run",))
    end = datetime.now(UTC)
    return await _service.collect(
        UUID(principal.tenant_id), "soc2", end - timedelta(hours=24), end,
        await _owner_user_id(principal),
    )


@router.get("/packs")
async def packs(
    framework: str | None = Query(default=None),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict]:
    principal.require(("compliance:read",))
    if framework and framework not in FRAMEWORKS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported framework")
    return await _service.list_packs(UUID(principal.tenant_id), framework)


async def _owner_user_id(principal: DeveloperPrincipal) -> UUID | None:
    app = await __import__("sentinel.storage.supabase_client", fromlist=["supabase"]).supabase.select_one(
        "developer_apps", "owner_user_id", id=principal.app_id
    )
    value = app.get("owner_user_id") if app else None
    try:
        return UUID(str(value)) if value else None
    except ValueError:
        return None
