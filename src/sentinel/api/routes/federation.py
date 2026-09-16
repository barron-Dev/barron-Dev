from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from sentinel.developer.auth import DeveloperPrincipal, authenticate_request
from sentinel.federation.anon import FederationAnonymizer
from sentinel.federation.reputation import FederationReputation
from sentinel.federation.stix import bundle_from_indicators, parse_stix_bundle
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/federation", tags=["threat-intelligence-federation"])
_reputation = FederationReputation()

PEER_KINDS = {"tenant", "cert", "isac", "vendor", "research"}
PEER_STATUSES = {"active", "paused", "blocked", "pending"}
IOC_TYPES = {"sha256", "domain", "ipv4", "ipv6", "url", "email", "ja3", "btc_address", "mutex"}
SEVERITIES = {"low", "medium", "high", "critical"}


def _require(principal: DeveloperPrincipal, scope: str) -> str:
    principal.require((scope,))
    return principal.tenant_id


class PeerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    kind: str = Field(pattern="^(tenant|cert|isac|vendor|research)$")
    external_id: str | None = Field(default=None, min_length=1, max_length=240)
    country: str | None = Field(default=None, min_length=2, max_length=8)
    taxii_url: str | None = Field(default=None, max_length=2048)
    taxii_collection: str | None = Field(default=None, max_length=240)
    auth_ref: str | None = Field(default=None, max_length=512)
    trust_level: int = Field(default=1, ge=0, le=3)
    share_categories: list[str] = Field(default_factory=list, max_length=100)
    receive_categories: list[str] = Field(default_factory=list, max_length=100)
    require_anonymization: bool = True


class PeerStatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|paused|blocked|pending)$")


class IndicatorIngest(BaseModel):
    peer_id: UUID
    source_tenant: UUID | None = None
    ioc_type: str
    value_hash: str = Field(pattern="^[0-9a-f]{64}$")
    value_ref: str | None = Field(default=None, max_length=4096)
    category: str | None = Field(default=None, max_length=120)
    severity: str = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class StixIngest(BaseModel):
    peer_id: UUID
    payload: str = Field(min_length=2, max_length=5_000_000)


@router.get("/peers")
async def list_peers(
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict[str, Any]]:
    tenant_id = _require(principal, "federation:read")

    async def _do():
        return await (await supabase._ensure()).table("federation_peers").select(
            "id,tenant_id,external_id,name,kind,country,taxii_url,taxii_collection,trust_level,reputation,share_categories,receive_categories,require_anonymization,status,last_share_at,last_receive_at,created_at"
        ).or_(f"tenant_id.eq.{tenant_id},tenant_id.is.null").order("created_at", desc=True).limit(500).execute()

    return list((await supabase._retry(_do, attempts=2)).data or [])


@router.post("/peers", status_code=status.HTTP_201_CREATED)
async def create_peer(
    body: PeerCreate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:manage")
    if body.taxii_url and not body.taxii_url.lower().startswith("https://"):
        raise HTTPException(400, "TAXII endpoints must use HTTPS")
    if body.kind == "tenant":
        if body.external_id is not None:
            raise HTTPException(400, "tenant peers cannot have external_id")
        bound_tenant = tenant_id
    else:
        if not body.external_id:
            raise HTTPException(400, "external peers require external_id")
        bound_tenant = None

    row = {
        **body.model_dump(exclude={"external_id"}),
        "tenant_id": bound_tenant,
        "external_id": body.external_id,
    }

    async def _do():
        return await (await supabase._ensure()).table("federation_peers").insert(row).select(
            "id,tenant_id,external_id,name,kind,country,taxii_url,taxii_collection,trust_level,reputation,share_categories,receive_categories,require_anonymization,status,created_at"
        ).single().execute()

    try:
        result = await supabase._retry(_do, attempts=2)
    except Exception as exc:
        raise HTTPException(409, "peer already exists or is invalid") from exc
    if not result.data:
        raise HTTPException(502, "peer persistence failed")
    return result.data


@router.patch("/peers/{peer_id}")
async def update_peer_status(
    peer_id: UUID,
    body: PeerStatusUpdate,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:manage")

    async def _do():
        return await (await supabase._ensure()).table("federation_peers").update({"status": body.status}).eq(
            "id", str(peer_id)
        ).or_(f"tenant_id.eq.{tenant_id},tenant_id.is.null").select(
            "id,tenant_id,external_id,name,kind,country,taxii_url,taxii_collection,trust_level,reputation,share_categories,receive_categories,require_anonymization,status"
        ).limit(1).execute()

    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "peer not found")
    return rows[0]


@router.get("/indicators")
async def list_indicators(
    ioc_type: str | None = None,
    verified: bool | None = None,
    severity: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> list[dict[str, Any]]:
    tenant_id = _require(principal, "federation:read")
    if ioc_type and ioc_type not in IOC_TYPES:
        raise HTTPException(400, "invalid IOC type")
    if severity and severity not in SEVERITIES:
        raise HTTPException(400, "invalid severity")

    async def _do():
        q = (await supabase._ensure()).table("fed_indicators").select(
            "id,source_peer_id,source_tenant,ioc_type,value_hash,value_ref,category,severity,confidence,sightings,distinct_peers,first_seen,last_seen,expires_at,verified,whitelisted,created_at"
        )
        if ioc_type:
            q = q.eq("ioc_type", ioc_type)
        if verified is not None:
            q = q.eq("verified", verified)
        if severity:
            q = q.eq("severity", severity)
        # The API is service-role backed, so explicitly constrain tenant-owned
        # observations while retaining platform/external intelligence.
        q = q.or_(f"source_tenant.eq.{tenant_id},source_tenant.is.null")
        return await q.order("last_seen", desc=True).limit(limit).execute()

    return list((await supabase._retry(_do, attempts=2)).data or [])


async def _validate_active_peer(peer_id: UUID, tenant_id: str) -> dict[str, Any]:
    async def _do():
        return await (await supabase._ensure()).table("federation_peers").select(
            "id,tenant_id,kind,status,trust_level,reputation,require_anonymization,share_categories,receive_categories"
        ).eq("id", str(peer_id)).limit(1).execute()

    rows = (await supabase._retry(_do, attempts=2)).data or []
    if not rows:
        raise HTTPException(404, "peer not found")
    peer = rows[0]
    if peer["status"] != "active":
        raise HTTPException(409, "peer is not active")
    if peer["kind"] == "tenant" and peer.get("tenant_id") != tenant_id:
        raise HTTPException(403, "peer is outside tenant boundary")
    return peer


@router.post("/indicators", status_code=status.HTTP_201_CREATED)
async def ingest_indicator(
    body: IndicatorIngest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:ingest")
    await _validate_active_peer(body.peer_id, tenant_id)
    if body.ioc_type not in IOC_TYPES:
        raise HTTPException(400, "invalid IOC type")
    if body.severity not in SEVERITIES:
        raise HTTPException(400, "invalid severity")
    if body.source_tenant is not None and str(body.source_tenant) != tenant_id:
        raise HTTPException(403, "source tenant must match authenticated tenant")

    value_ref = body.value_ref
    if value_ref:
        # Do not persist credential-bearing metadata supplied through the API.
        try:
            value_ref = FederationAnonymizer().redact_metadata({"value_ref": value_ref})["value_ref"]
        except RuntimeError:
            pass

    indicator_id = await supabase.rpc(
        "upsert_fed_indicator",
        {
            "p_peer": str(body.peer_id),
            "p_tenant": str(body.source_tenant) if body.source_tenant else None,
            "p_ioc_type": body.ioc_type,
            "p_value_hash": body.value_hash,
            "p_value_ref": value_ref,
            "p_category": body.category,
            "p_severity": body.severity,
            "p_confidence": body.confidence,
        },
    )
    return {"indicator_id": str(indicator_id), "accepted": True}


@router.post("/stix/ingest")
async def ingest_stix(
    body: StixIngest,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:ingest")
    await _validate_active_peer(body.peer_id, tenant_id)
    try:
        parsed = parse_stix_bundle(body.payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not parsed:
        raise HTTPException(400, "STIX bundle contains no supported indicators")

    accepted = 0
    for indicator in parsed[:5000]:
        try:
            await supabase.rpc(
                "upsert_fed_indicator",
                {
                    "p_peer": str(body.peer_id),
                    "p_tenant": None,
                    "p_ioc_type": indicator["ioc_type"],
                    "p_value_hash": indicator["value_hash"],
                    "p_value_ref": indicator["value_ref"],
                    "p_category": indicator.get("category"),
                    "p_severity": "medium",
                    "p_confidence": float(indicator.get("confidence", 0.5)),
                },
            )
            accepted += 1
        except Exception:
            # One malformed/unsupported indicator must not make the whole
            # bounded bundle transaction look successful.
            continue
    if accepted == 0:
        raise HTTPException(422, "no STIX indicators were accepted")
    return {"accepted": accepted, "received": len(parsed[:5000])}


@router.get("/stix/export")
async def export_stix(
    limit: int = Query(500, ge=1, le=5000),
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:export")

    async def _do():
        return await (await supabase._ensure()).table("fed_indicators").select(
            "id,ioc_type,value_hash,value_ref,category,confidence,created_at,last_seen"
        ).or_(f"source_tenant.eq.{tenant_id},source_tenant.is.null").eq("whitelisted", False).order(
            "last_seen", desc=True
        ).limit(limit).execute()

    indicators = list((await supabase._retry(_do, attempts=2)).data or [])
    if not indicators:
        return {"content_type": "application/stix+json;version=2.1", "sha256": hashlib.sha256(b"{}").hexdigest(), "bundle": {}}
    payload = bundle_from_indicators(indicators)
    return {
        "content_type": "application/stix+json;version=2.1",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bundle": payload.decode("utf-8"),
    }


@router.get("/peers/{peer_id}/reputation")
async def peer_reputation(
    peer_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    tenant_id = _require(principal, "federation:read")
    await _validate_active_peer(peer_id, tenant_id)
    reputation = await _reputation.get(peer_id=peer_id)
    if reputation is None:
        raise HTTPException(404, "peer not found")
    return {"peer_id": str(reputation.peer_id), "reputation": reputation.reputation}
