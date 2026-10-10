from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/darkweb", tags=["darkweb"])
WATCH_KINDS = {"email", "domain", "ip", "wallet", "phone", "company_name", "executive_name", "api_key_hash", "employee_id", "customer_id"}
ALIAS_KINDS = {"email", "domain", "company_name", "executive_name"}
STATUSES = {"new", "acknowledged", "investigating", "remediated", "false_positive"}


def _hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def _require(principal: DeveloperPrincipal, scope: str) -> UUID:
    principal.require((scope,))
    return UUID(principal.tenant_id)


class WatchCreate(BaseModel):
    kind: str = Field(min_length=2, max_length=32)
    value: str = Field(min_length=2, max_length=512)
    label: str | None = Field(default=None, max_length=200)
    severity: str = Field(default="high", pattern="^(medium|high|critical)$")


@router.post("/watchlist", status_code=status.HTTP_201_CREATED)
async def add_watch(body: WatchCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:manage")
    kind = body.kind.strip().lower()
    if kind not in WATCH_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported watchlist kind")
    value = body.value.strip().lower()
    row = {"tenant_id": str(tenant_id), "kind": kind, "value": value, "value_hash": _hash(value), "label": body.label, "severity": body.severity}
    async def _do():
        return await (await supabase._ensure()).table("dw_watchlist").insert(row).execute()
    try:
        data = (await supabase._retry(_do, attempts=2)).data or []
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(status.HTTP_409_CONFLICT, "watch already exists") from exc
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "watchlist persistence failed") from exc
    return data[0]


@router.get("/watchlist")
async def list_watch(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = _require(principal, "darkweb:read")
    async def _do():
        return await (await supabase._ensure()).table("dw_watchlist").select("id,kind,value,label,severity,created_at").eq("tenant_id", str(tenant_id)).order("created_at", desc=True).limit(1000).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.delete("/watchlist/{watch_id}", status_code=204)
async def delete_watch(watch_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> None:
    tenant_id = _require(principal, "darkweb:manage")
    async def _do():
        return await (await supabase._ensure()).table("dw_watchlist").delete().eq("id", str(watch_id)).eq("tenant_id", str(tenant_id)).execute()
    await supabase._retry(_do, attempts=2)


class AliasCreate(BaseModel):
    kind: str = Field(min_length=2, max_length=32)
    value: str = Field(min_length=2, max_length=512)
    label: str | None = Field(default=None, max_length=200)


@router.post("/watchlist/{watch_id}/aliases", status_code=status.HTTP_201_CREATED)
async def add_alias(watch_id: UUID, body: AliasCreate, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:manage")
    kind = body.kind.strip().lower()
    if kind not in ALIAS_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported alias kind")
    value = body.value.strip().lower()

    async def _watch():
        return await (await supabase._ensure()).table("dw_watchlist").select("id,tenant_id,kind").eq("id", str(watch_id)).eq("tenant_id", str(tenant_id)).limit(1).execute()
    watch_rows = (await supabase._retry(_watch, attempts=2)).data or []
    if not watch_rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "watch not found")
    if watch_rows[0]["kind"] != kind:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "alias kind must match watch kind")

    row = {"tenant_id": str(tenant_id), "watchlist_id": str(watch_id), "kind": kind, "value": value, "alias_hash": _hash(value), "label": body.label}
    async def _insert():
        return await (await supabase._ensure()).table("dw_watch_aliases").insert(row).execute()
    try:
        data = (await supabase._retry(_insert, attempts=2)).data or []
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(status.HTTP_409_CONFLICT, "alias already exists") from exc
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "alias persistence failed") from exc
    return data[0]


@router.get("/watchlist/{watch_id}/aliases")
async def list_aliases(watch_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = _require(principal, "darkweb:read")
    async def _do():
        return await (await supabase._ensure()).table("dw_watch_aliases").select("id,kind,value,label,created_at").eq("watchlist_id", str(watch_id)).eq("tenant_id", str(tenant_id)).order("created_at", desc=True).limit(500).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.delete("/watchlist/{watch_id}/aliases/{alias_id}", status_code=204)
async def delete_alias(watch_id: UUID, alias_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> None:
    tenant_id = _require(principal, "darkweb:manage")
    async def _do():
        return await (await supabase._ensure()).table("dw_watch_aliases").delete().eq("id", str(alias_id)).eq("watchlist_id", str(watch_id)).eq("tenant_id", str(tenant_id)).execute()
    await supabase._retry(_do, attempts=2)


class AlertPatch(BaseModel):
    status: str | None = Field(default=None)
    notes: str | None = Field(default=None, max_length=4000)
    assigned_to: UUID | None = None


@router.get("/alerts")
async def alerts(status_filter: str | None = Query(default=None, alias="status"), severity: str | None = None, limit: int = Query(default=200, ge=1, le=1000), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = _require(principal, "darkweb:read")
    if status_filter and status_filter not in STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid status")
    if severity and severity not in {"medium", "high", "critical"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid severity")
    async def _do():
        q = (await supabase._ensure()).table("dw_alerts").select("*").eq("tenant_id", str(tenant_id))
        if status_filter: q = q.eq("status", status_filter)
        if severity: q = q.eq("severity", severity)
        return await q.order("created_at", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.patch("/alerts/{alert_id}")
async def patch_alert(alert_id: UUID, body: AlertPatch, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:manage")
    patch: dict = {}
    if body.status:
        if body.status not in STATUSES: raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid status")
        patch["status"] = body.status
        if body.status == "acknowledged": patch["acknowledged_at"] = datetime.now(UTC).isoformat()
        if body.status == "remediated": patch["remediated_at"] = datetime.now(UTC).isoformat()
    if body.notes is not None: patch["notes"] = body.notes
    if body.assigned_to is not None: patch["assigned_to"] = str(body.assigned_to)
    if not patch: raise HTTPException(status.HTTP_400_BAD_REQUEST, "nothing to update")
    async def _do():
        return await (await supabase._ensure()).table("dw_alerts").update(patch).eq("id", str(alert_id)).eq("tenant_id", str(tenant_id)).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows: raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return rows[0]


@router.post("/alerts/{alert_id}/open-case", status_code=status.HTTP_201_CREATED)
async def open_case(alert_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:manage")
    async def _find():
        return await (await supabase._ensure()).table("dw_alerts").select("*").eq("id", str(alert_id)).eq("tenant_id", str(tenant_id)).limit(1).execute()
    rows = (await supabase._retry(_find, attempts=2)).data or []
    if not rows: raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    alert = rows[0]
    if alert.get("case_id"): return {"case_id": alert["case_id"], "existing": True}
    async def _number():
        return await (await supabase._ensure()).rpc("next_case_number", {"p_tenant": str(tenant_id)}).execute()
    try: number = (await supabase._retry(_number, attempts=1)).data
    except Exception: number = None
    case_number = number if isinstance(number, str) else f"C-{datetime.now(UTC):%Y%m}-{uuid4().hex[:6].upper()}"
    case = {"tenant_id": str(tenant_id), "case_number": case_number, "title": alert["title"][:200], "category": "data_breach", "severity": alert["severity"], "status": "open", "summary": alert.get("summary"), "evidence": [{"type": "darkweb_alert", "alert_id": str(alert_id), "finding_id": alert["finding_id"]}]}
    async def _insert(): return await (await supabase._ensure()).table("crime_cases").insert(case).execute()
    created = (await supabase._retry(_insert, attempts=2)).data or []
    if not created: raise HTTPException(status.HTTP_502_BAD_GATEWAY, "case creation failed")
    case_id = created[0]["id"]
    async def _link(): return await (await supabase._ensure()).table("dw_alerts").update({"case_id": case_id, "status": "investigating"}).eq("id", str(alert_id)).eq("tenant_id", str(tenant_id)).execute()
    await supabase._retry(_link, attempts=2)
    return created[0]





@router.get("/runs")
async def list_source_runs(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    """Return recent source-cycle telemetry, never raw findings or credentials."""
    _require(principal, "darkweb:read")
    async def _do():
        return await (await supabase._ensure()).table("dw_source_runs").select(
            "id,source_id,status,stage,progress_percent,discovered_count,processed_count,matched_count,alert_count,error_count,detail,started_at,updated_at,completed_at"
        ).order("started_at", desc=True).limit(100).execute()
    try:
        rows = (await supabase._retry(_do, attempts=2)).data or []
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "source process telemetry unavailable") from exc
    return list(rows)


@router.get("/sources")
async def list_sources(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    """Show source readiness and observed health without exposing credentials."""
    _require(principal, "darkweb:read")
    from cyclothone.darkweb.source_status import source_health

    async def _do():
        return await (await supabase._ensure()).table("dw_sources").select(
            "id,name,kind,enabled,last_pull_at,last_status,poll_interval_seconds"
        ).order("id").execute()

    try:
        rows = (await supabase._retry(_do, attempts=2)).data or []
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "source health unavailable") from exc
    return [source_health(row) for row in rows]


def _sanitize_global_detection(row: dict) -> dict:
    """Remove identifying payloads from unmatched, tenant-global detections.

    Raw identifiers may be used internally for exact watchlist matching, but
    must not be disclosed to every tenant merely because tenant_id is NULL.
    Only a small source-metadata allowlist is exposed for global detections.
    """
    safe_metadata_keys = {"exposure_layer", "published", "breach", "paste_id", "channel", "group"}
    metadata = row.get("source_metadata")
    safe_metadata = {
        key: value for key, value in metadata.items()
        if key in safe_metadata_keys and isinstance(value, (str, int, float, bool, type(None)))
    } if isinstance(metadata, dict) else {}
    sanitized = dict(row)
    sanitized["matched_value"] = "[redacted]"
    sanitized["context"] = "Public-source detection; identifier details are withheld until matched to an authorized tenant watchlist."
    sanitized["source_url"] = None
    sanitized["source_metadata"] = safe_metadata
    return sanitized


@router.get("/findings")
async def findings(
    source_id: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict]:
    tenant_id = _require(principal, "darkweb:read")
    async def _do():
        q = (await supabase._ensure()).table("dw_findings").select(
            "id,source_id,content_hash,kind,matched_value,context,source_url,source_metadata,severity,risk_score,risk_factors,alert_eligible,first_seen,tenant_id,watchlist_id,web_layer,access_mode,collected_at"
        ).or_(f"tenant_id.eq.{tenant_id},tenant_id.is.null")
        if source_id:
            q = q.eq("source_id", source_id)
        if severity:
            q = q.eq("severity", severity)
        return await q.order("first_seen", desc=True).limit(limit).execute()
    rows = list((await supabase._retry(_do, attempts=2)).data or [])
    # Prefer a tenant-scoped match over the corresponding sanitized global row,
    # avoiding duplicate detections when the same source item is both globally
    # collected and later matched to this tenant's authorized watchlist.
    tenant_match_keys = {
        (str(row.get("source_id")), str(row.get("kind")), str(row.get("matched_value", "")).strip().lower())
        for row in rows if row.get("tenant_id") is not None
    }
    visible = [
        row for row in rows
        if row.get("tenant_id") is not None
        or (str(row.get("source_id")), str(row.get("kind")), str(row.get("matched_value", "")).strip().lower()) not in tenant_match_keys
    ]
    # Global detections are shared only as sanitized records, never with raw
    # identifiers or payload URLs.
    return [
        _sanitize_global_detection(row) if row.get("tenant_id") is None else row
        for row in visible
    ]


@router.get("/sources")
async def sources(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    _require(principal, "darkweb:read")
    async def _do():
        return await (await supabase._ensure()).table("dw_sources").select(
            "id,name,kind,endpoint,enabled,last_pull_at,last_status,poll_interval_seconds,web_layer,access_mode,created_at"
        ).order("name").execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.get("/stats")
async def stats(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    tenant_id = _require(principal, "darkweb:read")
    async def _do(): return await (await supabase._ensure()).table("dw_alerts").select("status,severity").eq("tenant_id", str(tenant_id)).execute()
    rows = (await supabase._retry(_do, attempts=2)).data or []
    return {"total_alerts": len(rows), "new": sum(r.get("status") == "new" for r in rows), "critical": sum(r.get("severity") == "critical" for r in rows), "high": sum(r.get("severity") == "high" for r in rows), "remediated": sum(r.get("status") == "remediated" for r in rows)}


@router.get("/ransomware")
async def ransomware(country: str | None = None, limit: int = Query(default=200, ge=1, le=1000), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    tenant_id = _require(principal, "darkweb:read")
    async def _do():
        q = (await supabase._ensure()).table("ransomware_victims").select("*").or_(f"tenant_id.eq.{tenant_id},tenant_id.is.null")
        if country: q = q.eq("country", country)
        return await q.order("published_at", desc=True).limit(limit).execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])
