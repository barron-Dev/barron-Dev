from __future__ import annotations

import os
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.investigation.models import InvestigationEvidence, InvestigationRequest
from cyclothone.investigation.service import InvestigationControlPlane

router = APIRouter(prefix="/investigations", tags=["investigations"])


class InvestigationRequestBody(BaseModel):
    purpose: str = Field(min_length=1, max_length=500)
    authorization_ref: str = Field(min_length=1, max_length=500)
    provider: str = Field(min_length=1, max_length=120)
    case_id: UUID | None = None


class CompleteBody(BaseModel):
    summary: str | None = Field(default=None, max_length=4000)


class EvidenceBody(BaseModel):
    evidence_type: str
    sha256: str = Field(min_length=64, max_length=64)
    object_ref: str = Field(min_length=1)
    collected_at: datetime
    metadata: dict[str, object] = Field(default_factory=dict)


_control_plane = InvestigationControlPlane()


def _require(principal: DeveloperPrincipal, scope: str) -> DeveloperPrincipal:
    principal.require((scope,))
    return principal


def _principal_uuid(principal: DeveloperPrincipal) -> UUID | None:
    try:
        return UUID(principal.app_id)
    except ValueError:
        return None


@router.post("")
async def request_investigation(
    body: InvestigationRequestBody,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "investigation:request")
    request = InvestigationRequest(
        tenant_id=UUID(principal.tenant_id),
        case_id=body.case_id,
        created_by=_principal_uuid(principal),
        purpose=body.purpose,
        authorization_ref=body.authorization_ref,
        provider=body.provider,
    )
    try:
        return await _control_plane.request(request)
    except ValueError as exc:
        raise HTTPException(503, {"error": str(exc)}) from exc


@router.post("/{session_id}/start")
async def start_investigation(
    session_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "investigation:approve")
    try:
        return await _control_plane.approve_and_start(session_id, UUID(principal.tenant_id))
    except LookupError as exc:
        raise HTTPException(404, {"error": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc


@router.post("/{session_id}/stop")
async def stop_investigation(
    session_id: UUID,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "investigation:stop")
    try:
        return await _control_plane.stop(session_id, UUID(principal.tenant_id))
    except LookupError as exc:
        raise HTTPException(404, {"error": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc


@router.post("/{session_id}/complete")
async def complete_investigation(
    session_id: UUID,
    body: CompleteBody,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "investigation:complete")
    try:
        completed = await __import__("cyclothone.storage.supabase_client", fromlist=["supabase"]).supabase.rpc(
            "complete_investigation_session",
            {
                "p_session_id": str(session_id),
                "p_tenant_id": principal.tenant_id,
                "p_actor": f"console:{principal.app_id}",
                "p_summary": body.summary,
            },
        )
        return {"session_id": str(completed), "status": "completed"}
    except Exception as exc:
        message = str(exc)
        if "investigation_session_not_running" in message:
            raise HTTPException(409, {"error": "investigation_session_not_running"}) from exc
        raise HTTPException(503, {"error": "investigation completion unavailable"}) from exc


@router.post("/{session_id}/evidence")
async def record_evidence(
    session_id: UUID,
    body: EvidenceBody,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    _require(principal, "investigation:evidence")
    evidence = InvestigationEvidence(
        session_id=session_id,
        tenant_id=UUID(principal.tenant_id),
        evidence_type=body.evidence_type,
        sha256=body.sha256.lower(),
        object_ref=body.object_ref,
        collected_at=body.collected_at,
        metadata=body.metadata,
    )
    try:
        return await _control_plane.record_evidence(evidence)
    except LookupError as exc:
        raise HTTPException(404, {"error": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc
