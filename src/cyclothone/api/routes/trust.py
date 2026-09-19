from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


def _write(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:write",))
    return principal


class EvidenceRequest(BaseModel):
    subject_id: str
    evidence_type: str
    source_type: str
    source_id: str | None = Field(default=None, max_length=512)
    content_type: str | None = Field(default=None, max_length=256)
    content_uri: str | None = Field(default=None, max_length=2048)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    collected_at: datetime
    expires_at: datetime | None = None
    signature_algorithm: str | None = Field(default=None, max_length=64)
    signer_key_id: str | None = Field(default=None, max_length=256)
    signature: str | None = Field(default=None, max_length=16384)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateAttestationRequest(BaseModel):
    subject_id: str
    attestation_type: str
    verifier_type: str
    verifier_id: str = Field(min_length=1, max_length=256)
    verifier_version: str | None = Field(default=None, max_length=256)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)
    claims: dict[str, Any] = Field(default_factory=dict)
    valid_until: datetime | None = None


class VerifyAttestationRequest(BaseModel):
    status: str
    assurance_level: str
    claims: dict[str, Any] = Field(default_factory=dict)
    failure_reason: str | None = Field(default=None, max_length=2000)


@router.get("/subjects/{subject_id}/evidence")
async def list_evidence(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects",
        "id,tenant_id,subject_kind,external_ref,lifecycle_state",
        id=subject_id,
        tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select(
        "trust_evidence",
        "id,subject_id,evidence_type,source_type,source_id,content_type,content_uri,content_hash,evidence_hash,collected_at,expires_at,signature_algorithm,signer_key_id,metadata,created_at",
        subject_id=subject_id,
        tenant_id=principal.tenant_id,
    )
    return {"evidence": rows}


@router.post("/evidence")
async def record_evidence(body: EvidenceRequest, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id,lifecycle_state",
        id=body.subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    try:
        row = await supabase.rpc("trust_record_evidence", {
            "p_subject_id": body.subject_id,
            "p_evidence_type": body.evidence_type,
            "p_source_type": body.source_type,
            "p_source_id": body.source_id,
            "p_content_type": body.content_type,
            "p_content_uri": body.content_uri,
            "p_content_hash": body.content_hash,
            "p_collected_at": body.collected_at.isoformat(),
            "p_expires_at": body.expires_at.isoformat() if body.expires_at else None,
            "p_signature_algorithm": body.signature_algorithm,
            "p_signer_key_id": body.signer_key_id,
            "p_signature": body.signature,
            "p_metadata": body.metadata,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_evidence_rejected") from exc
    return {"evidence": row}


@router.get("/subjects/{subject_id}/attestations")
async def list_attestations(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id", id=subject_id, tenant_id=principal.tenant_id
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select(
        "trust_attestations",
        "id,subject_id,attestation_type,verifier_type,verifier_id,verifier_version,status,assurance_level,measurement_snapshot_hash,evidence_root_hash,valid_from,valid_until,claims,failure_reason,created_at,verified_at",
        subject_id=subject_id,
        tenant_id=principal.tenant_id,
    )
    return {"attestations": rows}


@router.post("/attestations")
async def create_attestation(
    body: CreateAttestationRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id", id=body.subject_id, tenant_id=principal.tenant_id
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    try:
        row = await supabase.rpc("trust_create_attestation", {
            "p_subject_id": body.subject_id,
            "p_attestation_type": body.attestation_type,
            "p_verifier_type": body.verifier_type,
            "p_verifier_id": body.verifier_id,
            "p_verifier_version": body.verifier_version,
            "p_evidence_ids": body.evidence_ids,
            "p_claims": body.claims,
            "p_valid_until": body.valid_until.isoformat() if body.valid_until else None,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_attestation_rejected") from exc
    return {"attestation": row}


@router.post("/attestations/{attestation_id}/verify")
async def verify_attestation(
    attestation_id: str,
    body: VerifyAttestationRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    row = await supabase.select_one(
        "trust_attestations",
        "id,tenant_id,subject_id,status",
        id=attestation_id,
        tenant_id=principal.tenant_id,
    )
    if not row:
        raise HTTPException(404, "trust_attestation_not_found")
    try:
        result = await supabase.rpc("trust_verify_attestation", {
            "p_attestation_id": attestation_id,
            "p_status": body.status,
            "p_assurance_level": body.assurance_level,
            "p_claims": body.claims,
            "p_failure_reason": body.failure_reason,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_attestation_verification_rejected") from exc
    return {"attestation": result}


class ComputeTrustStateRequest(BaseModel):
    subject_id: str


@router.get("/subjects/{subject_id}/state")
async def get_trust_state(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id,subject_kind,external_ref,lifecycle_state",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    state = await supabase.select_one(
        "trust_current_state",
        "subject_id,tenant_id,state,assurance_level,state_hash,reason,computed_at",
        subject_id=subject_id, tenant_id=principal.tenant_id,
    )
    return {"subject": subject, "state": state}


@router.get("/subjects/{subject_id}/state/history")
async def get_trust_state_history(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select(
        "trust_state_snapshots",
        "id,subject_id,state,assurance_level,measurement_count,valid_measurement_count,evidence_count,valid_evidence_count,verified_attestation_count,latest_measurement_at,latest_evidence_at,latest_attestation_at,state_reason,state_hash,computed_at",
        subject_id=subject_id, tenant_id=principal.tenant_id,
    )
    return {"history": rows}


@router.post("/subjects/{subject_id}/state/compute")
async def compute_trust_state(subject_id: str, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    try:
        state = await supabase.rpc("trust_compute_state", {"p_subject_id": subject_id})
    except Exception as exc:
        raise HTTPException(400, "trust_state_computation_rejected") from exc
    return {"state": state}
