from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from sentinel.compliance.catalog import FRAMEWORKS
from sentinel.compliance.pack import EvidencePackBuilder
from sentinel.compliance.service import ComplianceError, ComplianceService
from sentinel.compliance.signing import sign_digest
from sentinel.compliance.verification import ComplianceVerificationError, EvidencePackVerifier
from sentinel.developer.auth import DeveloperPrincipal, authenticate_request
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/compliance", tags=["compliance"])
_service = ComplianceService()
_builder = EvidencePackBuilder()
_verifier = EvidencePackVerifier()

class ComplianceRunRequest(BaseModel):
    framework: str = Field(min_length=2, max_length=32)
    period_start: datetime
    period_end: datetime

class AttestRequest(BaseModel):
    control_id: str = Field(min_length=3, max_length=64)
    statement: str = Field(min_length=10, max_length=2000)
    snapshot_id: UUID | None = None

@router.get("/frameworks")
async def frameworks(principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    return await _service.list_frameworks(UUID(principal.tenant_id))

@router.get("/controls")
async def controls(framework: str = Query(min_length=2, max_length=32), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    try:
        return await _service.list_controls(UUID(principal.tenant_id), framework)
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

@router.get("/assurance")
async def assurance(framework: str = Query(min_length=2, max_length=32), period_start: datetime = Query(...), period_end: datetime = Query(...), principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:read",))
    try:
        return await _service.assurance(UUID(principal.tenant_id), framework, period_start, period_end)
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

@router.post("/runs", status_code=status.HTTP_201_CREATED)
async def run_compliance(body: ComplianceRunRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:run",))
    try:
        return await _service.evaluate(UUID(principal.tenant_id), body.framework, body.period_start, body.period_end, await _owner_user_id(principal))
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

@router.post("/runs/last-24h", status_code=status.HTTP_201_CREATED)
async def run_last_24h(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:run",))
    end = datetime.now(UTC)
    return await _service.evaluate(UUID(principal.tenant_id), "soc2", end - timedelta(hours=24), end, await _owner_user_id(principal))

@router.post("/packs", status_code=status.HTTP_201_CREATED)
async def build_pack(framework: str = Query(min_length=2, max_length=32), period_days: int = Query(default=90, ge=7, le=730), principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:run",))
    try:
        end = datetime.now(UTC)
        await _service.evaluate(UUID(principal.tenant_id), framework, end - timedelta(days=period_days), end, await _owner_user_id(principal))
        return await _builder.build(UUID(principal.tenant_id), framework, period_days, await _owner_user_id(principal))
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

@router.get("/packs")
async def packs(framework: str | None = Query(default=None), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    if framework and framework not in FRAMEWORKS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported framework")
    async def _do():
        q = (await supabase._ensure()).table("compliance_evidence_snapshots").select("id,framework_id,period_start,period_end,status,overall_score,controls_passing,controls_total,pack_sha256,manifest_sha256,signature,signer_kid,evidence_count,verification_status,created_at,pack_path").eq("tenant_id", principal.tenant_id).order("created_at", desc=True).limit(100)
        if framework:
            q = q.eq("framework_id", framework)
        return await q.execute()
    return list((await supabase._retry(_do, attempts=2)).data or [])

@router.post("/packs/{snapshot_id}/verify")
async def verify_pack(snapshot_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:read",))
    try:
        result = await _verifier.verify(UUID(principal.tenant_id), snapshot_id)
    except ComplianceVerificationError as exc:
        if str(exc) == "snapshot not found":
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {"snapshot_id": result.snapshot_id, "verified": result.verified, "pack_sha256": result.pack_sha256, "manifest_sha256": result.manifest_sha256, "signer_kid": result.signer_kid, "checks": result.checks}

@router.get("/packs/{snapshot_id}/download")
async def download_pack(snapshot_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)) -> Response:
    principal.require(("compliance:read",))
    async def _find():
        return await (await supabase._ensure()).table("compliance_evidence_snapshots").select("pack_path,pack_sha256").eq("id", str(snapshot_id)).eq("tenant_id", principal.tenant_id).limit(1).execute()
    rows = (await supabase._retry(_find, attempts=2)).data or []
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "snapshot not found")
    try:
        async def _dl():
            return await (await supabase._ensure()).storage.from_("compliance").download(rows[0]["pack_path"])
        data = await supabase._retry(_dl, attempts=3)
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "storage error") from exc
    if hashlib.sha256(data).hexdigest() != rows[0]["pack_sha256"]:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "stored pack integrity check failed")
    return Response(content=data, media_type="application/zip", headers={"content-disposition": f'attachment; filename="evidence-{snapshot_id}.zip"', "x-pack-sha256": rows[0]["pack_sha256"]})

@router.post("/attest", status_code=status.HTTP_201_CREATED)
async def attest(body: AttestRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:attest",))
    tenant_id = UUID(principal.tenant_id)
    attested_by = await _owner_user_id(principal)
    if attested_by is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "authenticated developer app has no owner user")
    async def _control():
        return await (await supabase._ensure()).table("compliance_controls").select("id,stable_id,framework,control_code").eq("stable_id", body.control_id).limit(1).execute()
    controls = (await supabase._retry(_control, attempts=2)).data or []
    if not controls:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")
    snapshot_id = str(body.snapshot_id) if body.snapshot_id else None
    if snapshot_id:
        async def _snapshot():
            return await (await supabase._ensure()).table("compliance_evidence_snapshots").select("id").eq("id", snapshot_id).eq("tenant_id", str(tenant_id)).limit(1).execute()
        if not ((await supabase._retry(_snapshot, attempts=2)).data or []):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "snapshot not found")
    statement_sha = hashlib.sha256(body.statement.encode()).hexdigest()
    signed = await sign_digest(statement_sha)
    row = {"tenant_id":str(tenant_id),"control_id":controls[0]["id"],"snapshot_id":snapshot_id,"attested_by":str(attested_by),"statement":body.statement,"statement_sha256":statement_sha,"signature":signed.signature_b64,"signer_kid":signed.kid}
    async def _insert():
        return await (await supabase._ensure()).table("compliance_attestations").insert(row).execute()
    try:
        return ((await supabase._retry(_insert, attempts=2)).data or [{}])[0]
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "attestation persistence failed") from exc

async def _owner_user_id(principal: DeveloperPrincipal) -> UUID | None:
    app = await supabase.select_one("developer_apps", "owner_user_id", id=principal.app_id)
    value = app.get("owner_user_id") if app else None
    try:
        return UUID(str(value)) if value else None
    except (TypeError, ValueError):
        return None
