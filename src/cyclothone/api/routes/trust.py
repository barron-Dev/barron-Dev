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


class TrustSubjectRegistration(BaseModel):
    subject_kind: str
    external_ref: str = Field(min_length=1, max_length=512)
    display_name: str | None = Field(default=None, max_length=200)
    provider_id: str | None = Field(default=None, max_length=256)
    version: str | None = Field(default=None, max_length=256)
    identity_document: dict[str, Any] = Field(default_factory=dict)
    public_key_algorithm: str | None = Field(default=None, max_length=64)
    public_key: str | None = Field(default=None, max_length=8192)
    key_id: str | None = Field(default=None, max_length=256)


class TrustMeasurementRequest(BaseModel):
    subject_id: str
    measurement_type: str
    algorithm: str
    measurement_value: str = Field(min_length=1, max_length=4096)
    source_type: str
    source_id: str | None = Field(default=None, max_length=512)
    collected_at: datetime
    evidence_uri: str | None = Field(default=None, max_length=2048)
    evidence_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get("/subjects")
async def list_subjects(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    rows = await supabase.select(
        "trust_subjects",
        "id,tenant_id,subject_kind,external_ref,display_name,provider_id,version,identity_document,public_key_algorithm,key_id,lifecycle_state,created_at,updated_at",
        tenant_id=principal.tenant_id,
    )
    return {"subjects": rows}


@router.post("/subjects")
async def register_subject(
    body: TrustSubjectRegistration,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    try:
        row = await supabase.rpc(
            "trust_register_subject",
            {
                "p_tenant_id": principal.tenant_id,
                "p_subject_kind": body.subject_kind,
                "p_external_ref": body.external_ref,
                "p_display_name": body.display_name,
                "p_provider_id": body.provider_id,
                "p_version": body.version,
                "p_identity_document": body.identity_document,
                "p_public_key_algorithm": body.public_key_algorithm,
                "p_public_key": body.public_key,
                "p_key_id": body.key_id,
                "p_created_by": principal.user_id,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="trust_subject_registration_rejected") from exc
    return {"subject": row}


@router.get("/subjects/{subject_id}/measurements")
async def list_measurements(
    subject_id: str,
    principal: DeveloperPrincipal = Depends(_read),
) -> dict:
    subject = await supabase.select_one(
        "trust_subjects",
        "id,tenant_id,subject_kind,external_ref,lifecycle_state",
        id=subject_id,
        tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(status_code=404, detail="trust_subject_not_found")

    rows = await supabase.select(
        "trust_measurements",
        "id,subject_id,measurement_type,algorithm,measurement_value,measurement_hash,source_type,source_id,collected_at,received_at,evidence_uri,evidence_hash,metadata,sequence_no,created_at",
        subject_id=subject_id,
        tenant_id=principal.tenant_id,
    )
    return {"subject": subject, "measurements": rows}


@router.post("/subjects/{subject_id}/measurements")
async def record_measurement(
    subject_id: str,
    body: TrustMeasurementRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    subject = await supabase.select_one(
        "trust_subjects",
        "id,tenant_id,subject_kind,external_ref,lifecycle_state",
        id=subject_id,
        tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(status_code=404, detail="trust_subject_not_found")

    try:
        row = await supabase.rpc(
            "trust_record_measurement",
            {
                "p_subject_id": subject_id,
                "p_measurement_type": body.measurement_type,
                "p_algorithm": body.algorithm,
                "p_measurement_value": body.measurement_value,
                "p_source_type": body.source_type,
                "p_source_id": body.source_id,
                "p_collected_at": body.collected_at.isoformat(),
                "p_evidence_uri": body.evidence_uri,
                "p_evidence_hash": body.evidence_hash,
                "p_metadata": body.metadata,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="trust_measurement_rejected") from exc

    return {"measurement": row}
