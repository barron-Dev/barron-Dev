from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends

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
