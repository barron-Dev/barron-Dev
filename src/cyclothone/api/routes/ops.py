from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/ops", tags=["security-operations"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


async def _count(table: str, tenant_id: str) -> int:
    try:
        client = await supabase._ensure()
        result = await client.table(table).select("id", count="exact", head=True).eq("tenant_id", tenant_id).execute()
        return int(result.count or 0)
    except Exception:
        return -1


@router.get("/readiness")
async def security_operations_readiness(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    tenant_id = principal.tenant_id
    checks = {
        "database": False,
        "detection_store": False,
        "case_store": False,
        "investigation_store": False,
        "intelligence_store": False,
        "darkweb_sources": False,
        "physical_correlation_store": False,
    }
    counts: dict[str, int] = {}
    try:
        client = await supabase._ensure()
        await client.table("tenants").select("id").eq("id", tenant_id).single().execute()
        checks["database"] = True
        for key, table in (
            ("detections", "detections"),
            ("cases", "crime_cases"),
            ("investigations", "investigation_sessions"),
            ("indicators", "indicators"),
            ("physical_correlations", "physical_digital_correlations"),
        ):
            counts[key] = await _count(table, tenant_id)
        checks["detection_store"] = counts["detections"] >= 0
        checks["case_store"] = counts["cases"] >= 0
        checks["investigation_store"] = counts["investigations"] >= 0
        checks["intelligence_store"] = counts["indicators"] >= 0
        checks["physical_correlation_store"] = counts["physical_correlations"] >= 0
        source_rows = (await client.table("dw_sources").select("id,last_pull_at,last_status").eq("enabled", True).execute()).data or []
        checks["darkweb_sources"] = all(row.get("last_status") in ("ok", "degraded", None) for row in source_rows)
        sources = [{"id": row.get("id"), "last_pull_at": row.get("last_pull_at"), "last_status": row.get("last_status")} for row in source_rows]
    except Exception:
        sources = []

    ready = checks["database"] and all(checks.values())
    return {
        "status": "READY" if ready else "DEGRADED",
        "checks": checks,
        "counts": counts,
        "darkweb_sources": sources,
        "tenant_id": tenant_id,
        "checked_at": datetime.now(UTC).isoformat(),
    }
