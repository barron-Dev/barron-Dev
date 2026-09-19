from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import base64
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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


class CreateTrustProofRequest(BaseModel):
    state_snapshot_id: str
    attestation_id: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


@router.get("/subjects/{subject_id}/proofs")
async def list_trust_proofs(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id,subject_kind,external_ref",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select(
        "trust_proofs",
        "id,subject_id,state_snapshot_id,attestation_id,state,assurance_level,measurement_root_hash,evidence_root_hash,attestation_root_hash,subject_identity_hash,proof_hash,claims,signature_algorithm,signer_key_id,created_at",
        subject_id=subject_id, tenant_id=principal.tenant_id,
    )
    return {"proofs": rows}


@router.get("/proofs/{proof_id}")
async def get_trust_proof(proof_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    row = await supabase.select_one(
        "trust_proofs",
        "id,tenant_id,subject_id,state_snapshot_id,attestation_id,state,assurance_level,measurement_root_hash,evidence_root_hash,attestation_root_hash,subject_identity_hash,proof_hash,claims,signature_algorithm,signer_key_id,created_at",
        id=proof_id, tenant_id=principal.tenant_id,
    )
    if not row:
        raise HTTPException(404, "trust_proof_not_found")
    return {"proof": row}


@router.post("/subjects/{subject_id}/proofs")
async def create_trust_proof(
    subject_id: str,
    body: CreateTrustProofRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    try:
        row = await supabase.rpc("trust_create_proof", {
            "p_subject_id": subject_id,
            "p_state_snapshot_id": body.state_snapshot_id,
            "p_attestation_id": body.attestation_id,
            "p_claims": body.claims,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_proof_rejected") from exc
    return {"proof": row}


class SignTrustProofRequest(BaseModel):
    key_id: str
    signature: str


@router.get("/proofs/{proof_id}/signatures")
async def list_trust_proof_signatures(proof_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    proof = await supabase.select_one(
        "trust_proofs", "id,tenant_id,subject_id,proof_hash",
        id=proof_id, tenant_id=principal.tenant_id,
    )
    if not proof:
        raise HTTPException(404, "trust_proof_not_found")
    rows = await supabase.select(
        "trust_proof_signatures",
        "id,proof_id,key_id,algorithm,signature,signed_payload_hash,created_at",
        proof_id=proof_id, tenant_id=principal.tenant_id,
    )
    return {"signatures": rows}


@router.post("/proofs/{proof_id}/sign")
async def sign_trust_proof(
    proof_id: str,
    body: SignTrustProofRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    proof = await supabase.select_one(
        "trust_proofs", "id,tenant_id,proof_hash",
        id=proof_id, tenant_id=principal.tenant_id,
    )
    if not proof:
        raise HTTPException(404, "trust_proof_not_found")
    key = await supabase.select_one(
        "trust_signing_keys",
        "key_id,algorithm,purpose,public_key,status,not_before,not_after",
        tenant_id=principal.tenant_id,
        key_id=body.key_id,
    )
    if not key or key["purpose"] != "TRUST_PROOF" or key["algorithm"] != "ED25519":
        raise HTTPException(400, "trust_proof_signing_key_not_found")
    now = datetime.now(timezone.utc)
    if key["status"] != "ACTIVE" or now < datetime.fromisoformat(key["not_before"].replace("Z","+00:00")) or (
        key["not_after"] and now >= datetime.fromisoformat(key["not_after"].replace("Z","+00:00"))
    ):
        raise HTTPException(400, "trust_proof_signing_key_not_active")
    _verify_ed25519(key["public_key"], body.signature, bytes.fromhex(proof["proof_hash"]))
    try:
        row = await supabase.rpc("trust_sign_proof", {
            "p_proof_id": proof_id,
            "p_key_id": body.key_id,
            "p_signature": body.signature,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_proof_signing_rejected") from exc
    return {"signature": row}


class RegisterTrustKeyRequest(BaseModel):
    tenant_id: str
    key_id: str = Field(min_length=3, max_length=256)
    purpose: str
    public_key: str = Field(min_length=32, max_length=256)
    not_before: datetime | None = None
    not_after: datetime | None = None


class CreateCertificateProfileRequest(BaseModel):
    profile_id: str = Field(min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)
    display_name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=2000)
    required_assurance: str = "BASIC"
    max_validity_seconds: int = Field(default=86400, ge=60, le=31536000)


class IssueCertificateRequest(BaseModel):
    profile_id: str
    proof_id: str
    state_snapshot_id: str
    proof_signature_id: str
    issuer_key_id: str
    claims: dict[str, Any] = Field(default_factory=dict)
    valid_for_seconds: int = Field(default=86400, ge=60, le=31536000)
    certificate_signature: str = Field(min_length=32, max_length=16384)


class CertificateStatusRequest(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=2000)


def _b64u_decode(value: str) -> bytes:
    raw = value.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> None:
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64u_decode(public_key))
        key.verify(_b64u_decode(signature), message)
    except (ValueError, TypeError, InvalidSignature, UnicodeEncodeError, base64.binascii.Error) as exc:
        raise HTTPException(400, "trust_signature_invalid") from exc


def _certificate_payload(
    *,
    payload_version: int,
    certificate_id: str,
    serial_number: str,
    profile_id: str,
    profile_version: int,
    subject_id: str,
    proof_id: str,
    state_snapshot_id: str,
    proof_signature_id: str,
    proof_hash: str,
    state_hash: str,
    state: str,
    assurance_level: str,
    issuer_key_id: str,
    valid_from: datetime,
    valid_until: datetime,
    claims: dict[str, Any],
) -> bytes:
    payload = {
        "payload_version": payload_version,
        "certificate_id": certificate_id,
        "serial_number": serial_number,
        "profile_id": profile_id,
        "profile_version": profile_version,
        "subject_id": subject_id,
        "proof_id": proof_id,
        "state_snapshot_id": state_snapshot_id,
        "proof_signature_id": proof_signature_id,
        "proof_hash": proof_hash,
        "state_hash": state_hash,
        "state": state,
        "assurance_level": assurance_level,
        "issuer_key_id": issuer_key_id,
        "valid_from": valid_from.astimezone(timezone.utc).isoformat(),
        "valid_until": valid_until.astimezone(timezone.utc).isoformat(),
        "claims": claims,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


async def _load_certificate_material(certificate_id: str, principal: DeveloperPrincipal | None = None) -> dict[str, Any]:
    tenant_id = principal.tenant_id if principal else None
    filters = {"id": certificate_id}
    if tenant_id:
        filters["tenant_id"] = tenant_id
    cert = await supabase.select_one(
        "trust_certificates",
        "id,tenant_id,serial_number,profile_id,subject_id,proof_id,state_snapshot_id,proof_signature_id,issuer_key_id,algorithm,payload_version,payload_hash,signature,claims,issued_at,valid_from,valid_until,status,revoked_at,revocation_reason,suspended_at,suspension_reason",
        **filters,
    )
    if not cert:
        raise HTTPException(404, "trust_certificate_not_found")
    proof = await supabase.select_one(
        "trust_proofs",
        "id,subject_id,state_snapshot_id,state,assurance_level,proof_hash",
        id=cert["proof_id"], subject_id=cert["subject_id"],
    )
    snapshot = await supabase.select_one(
        "trust_state_snapshots",
        "id,subject_id,state,assurance_level,state_hash,computed_at",
        id=cert["state_snapshot_id"], subject_id=cert["subject_id"],
    )
    profile = await supabase.select_one(
        "trust_certificate_profiles",
        "id,profile_id,version,display_name,required_state,required_assurance,max_validity_seconds",
        id=cert["profile_id"],
    )
    proof_sig = await supabase.select_one(
        "trust_proof_signatures",
        "id,proof_id,key_id,algorithm,signature,signed_payload_hash",
        id=cert["proof_signature_id"], proof_id=cert["proof_id"],
    )
    key = await supabase.select_one(
        "trust_signing_keys",
        "id,tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after",
        tenant_id=cert["tenant_id"], key_id=cert["issuer_key_id"],
    )
    if not all((proof, snapshot, profile, proof_sig, key)):
        raise HTTPException(409, "trust_certificate_chain_incomplete")
    return {"certificate": cert, "proof": proof, "snapshot": snapshot, "profile": profile, "proof_signature": proof_sig, "key": key}


@router.post("/keys")
async def register_trust_key(body: RegisterTrustKeyRequest, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    if body.tenant_id != principal.tenant_id:
        raise HTTPException(403, "tenant_scope_violation")
    try:
        _b64u_decode(body.public_key)
    except Exception as exc:
        raise HTTPException(400, "invalid_trust_public_key_encoding") from exc
    if len(_b64u_decode(body.public_key)) != 32:
        raise HTTPException(400, "invalid_trust_public_key_length")
    try:
        row = await supabase.rpc("trust_register_signing_key", {
            "p_tenant_id": body.tenant_id,
            "p_key_id": body.key_id,
            "p_algorithm": "ED25519",
            "p_purpose": body.purpose,
            "p_public_key": body.public_key,
            "p_not_before": (body.not_before or datetime.now(timezone.utc)).isoformat(),
            "p_not_after": body.not_after.isoformat() if body.not_after else None,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_key_registration_rejected") from exc
    return {"key": row}


@router.post("/certificate-profiles")
async def create_certificate_profile(
    body: CreateCertificateProfileRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    if body.required_assurance not in {"NONE", "BASIC", "MEASURED", "HARDWARE_BACKED", "CRYPTOGRAPHIC"}:
        raise HTTPException(400, "invalid_assurance_level")
    try:
        row = await supabase.insert("trust_certificate_profiles", {
            "tenant_id": principal.tenant_id,
            "profile_id": body.profile_id,
            "version": body.version,
            "display_name": body.display_name,
            "description": body.description,
            "required_state": "VERIFIED",
            "required_assurance": body.required_assurance,
            "max_validity_seconds": body.max_validity_seconds,
            "required_proof_signature": True,
            "status": "ACTIVE",
        })
    except Exception as exc:
        raise HTTPException(400, "trust_certificate_profile_rejected") from exc
    return {"profile": row}


@router.get("/subjects/{subject_id}/certificates")
async def list_certificates(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id,subject_kind,external_ref,lifecycle_state",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select(
        "trust_certificates",
        "id,serial_number,profile_id,subject_id,proof_id,state_snapshot_id,proof_signature_id,issuer_key_id,algorithm,payload_version,payload_hash,claims,issued_at,valid_from,valid_until,status,revoked_at,revocation_reason,suspended_at,suspension_reason",
        subject_id=subject_id, tenant_id=principal.tenant_id,
    )
    return {"certificates": rows}


@router.get("/certificates/{certificate_id}")
async def get_certificate(certificate_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    material = await _load_certificate_material(certificate_id, principal)
    cert = material["certificate"].copy()
    cert.pop("signature", None)
    return {"certificate": cert}


@router.post("/subjects/{subject_id}/certificates")
async def issue_certificate(
    subject_id: str,
    body: IssueCertificateRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    subject = await supabase.select_one(
        "trust_subjects", "id,tenant_id,lifecycle_state",
        id=subject_id, tenant_id=principal.tenant_id,
    )
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    proof = await supabase.select_one(
        "trust_proofs",
        "id,subject_id,state_snapshot_id,state,assurance_level,proof_hash",
        id=body.proof_id, subject_id=subject_id,
    )
    snapshot = await supabase.select_one(
        "trust_state_snapshots",
        "id,subject_id,state,assurance_level,state_hash,computed_at",
        id=body.state_snapshot_id, subject_id=subject_id,
    )
    if not proof or not snapshot or proof["state_snapshot_id"] != snapshot["id"]:
        raise HTTPException(400, "trust_certificate_binding_invalid")
    proof_sig = await supabase.select_one(
        "trust_proof_signatures",
        "id,proof_id,key_id,algorithm,signature,signed_payload_hash",
        id=body.proof_signature_id, proof_id=body.proof_id,
    )
    if not proof_sig or proof_sig["signed_payload_hash"] != proof["proof_hash"]:
        raise HTTPException(400, "trust_proof_signature_binding_invalid")
    proof_key = await supabase.select_one(
        "trust_signing_keys",
        "id,tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after",
        tenant_id=principal.tenant_id, key_id=proof_sig["key_id"],
    )
    if not proof_key or proof_key["purpose"] != "TRUST_PROOF":
        raise HTTPException(400, "trust_proof_signing_key_not_found")
    _verify_ed25519(proof_key["public_key"], proof_sig["signature"], bytes.fromhex(proof["proof_hash"]))

    profile = await supabase.select_one(
        "trust_certificate_profiles",
        "id,profile_id,version,required_state,required_assurance,max_validity_seconds,status",
        id=body.profile_id, tenant_id=principal.tenant_id,
    )
    if not profile or profile["status"] != "ACTIVE":
        raise HTTPException(400, "trust_certificate_profile_not_active")
    if snapshot["state"] != "VERIFIED" or proof["state"] != snapshot["state"]:
        raise HTTPException(400, "trust_state_not_certifiable")
    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(seconds=min(body.valid_for_seconds, profile["max_validity_seconds"]))
    serial = f"CT-{now.strftime('%Y%m%d')}-{secrets.token_hex(12).upper()}"
    payload = _certificate_payload(
        payload_version=1,
        certificate_id=serial,
        serial_number=serial,
        profile_id=profile["profile_id"],
        profile_version=profile["version"],
        subject_id=subject_id,
        proof_id=body.proof_id,
        state_snapshot_id=body.state_snapshot_id,
        proof_signature_id=body.proof_signature_id,
        proof_hash=proof["proof_hash"],
        state_hash=snapshot["state_hash"],
        state=snapshot["state"],
        assurance_level=snapshot["assurance_level"],
        issuer_key_id=body.issuer_key_id,
        valid_from=now,
        valid_until=valid_until,
        claims=body.claims,
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    cert_key = await supabase.select_one(
        "trust_signing_keys",
        "id,tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after",
        tenant_id=principal.tenant_id, key_id=body.issuer_key_id,
    )
    if not cert_key or cert_key["purpose"] != "TRUST_CERTIFICATE" or cert_key["algorithm"] != "ED25519":
        raise HTTPException(400, "trust_certificate_signing_key_not_found")
    if cert_key["status"] != "ACTIVE":
        raise HTTPException(400, "trust_certificate_signing_key_not_active")
    key_now = datetime.now(timezone.utc)
    key_not_before = datetime.fromisoformat(cert_key["not_before"].replace("Z","+00:00"))
    key_not_after = datetime.fromisoformat(cert_key["not_after"].replace("Z","+00:00")) if cert_key["not_after"] else None
    if key_now < key_not_before or (key_not_after and key_now >= key_not_after):
        raise HTTPException(400, "trust_certificate_signing_key_not_active")
    _verify_ed25519(cert_key["public_key"], body.certificate_signature, bytes.fromhex(payload_hash))
    try:
        row = await supabase.rpc("trust_issue_certificate", {
            "p_serial_number": serial,
            "p_profile_id": profile["id"],
            "p_subject_id": subject_id,
            "p_proof_id": body.proof_id,
            "p_state_snapshot_id": body.state_snapshot_id,
            "p_proof_signature_id": body.proof_signature_id,
            "p_issuer_key_id": body.issuer_key_id,
            "p_payload_hash": payload_hash,
            "p_signature": body.certificate_signature,
            "p_claims": body.claims,
            "p_valid_from": now.isoformat(),
            "p_valid_until": valid_until.isoformat(),
        })
    except Exception as exc:
        raise HTTPException(400, "trust_certificate_issuance_rejected") from exc
    return {"certificate": row, "payload": payload.decode("utf-8")}


@router.post("/certificates/{certificate_id}/status")
async def update_certificate_status(
    certificate_id: str,
    body: CertificateStatusRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    cert = await supabase.select_one(
        "trust_certificates", "id,tenant_id",
        id=certificate_id, tenant_id=principal.tenant_id,
    )
    if not cert:
        raise HTTPException(404, "trust_certificate_not_found")
    try:
        row = await supabase.rpc("trust_update_certificate_status", {
            "p_certificate_id": certificate_id,
            "p_status": body.status,
            "p_reason": body.reason,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_certificate_status_rejected") from exc
    return {"certificate": row}


@router.get("/certificates/{certificate_id}/verify")
async def verify_certificate(certificate_id: str) -> dict:
    material = await _load_certificate_material(certificate_id)
    cert = material["certificate"]
    proof = material["proof"]
    snapshot = material["snapshot"]
    profile = material["profile"]
    proof_sig = material["proof_signature"]
    key = material["key"]

    now = datetime.now(timezone.utc)
    reasons: list[str] = []
    proof_ok = True
    cert_ok = True
    try:
        proof_key = await supabase.select_one(
            "trust_signing_keys",
            "public_key,algorithm,purpose,status,not_before,not_after",
            tenant_id=cert["tenant_id"], key_id=proof_sig["key_id"],
        )
        if not proof_key or proof_key["purpose"] != "TRUST_PROOF":
            raise ValueError("proof_key_missing")
        _verify_ed25519(proof_key["public_key"], proof_sig["signature"], bytes.fromhex(proof["proof_hash"]))
    except Exception:
        proof_ok = False
        reasons.append("proof_signature_invalid")

    try:
        payload = _certificate_payload(
            payload_version=cert["payload_version"],
            certificate_id=cert["serial_number"],
            serial_number=cert["serial_number"],
            profile_id=profile["profile_id"],
            profile_version=profile["version"],
            subject_id=cert["subject_id"],
            proof_id=cert["proof_id"],
            state_snapshot_id=cert["state_snapshot_id"],
            proof_signature_id=cert["proof_signature_id"],
            proof_hash=proof["proof_hash"],
            state_hash=snapshot["state_hash"],
            state=snapshot["state"],
            assurance_level=snapshot["assurance_level"],
            issuer_key_id=cert["issuer_key_id"],
            valid_from=datetime.fromisoformat(cert["valid_from"].replace("Z","+00:00")),
            valid_until=datetime.fromisoformat(cert["valid_until"].replace("Z","+00:00")),
            claims=cert["claims"],
        )
        expected_hash = hashlib.sha256(payload).hexdigest()
        if expected_hash != cert["payload_hash"]:
            raise ValueError("payload_hash_mismatch")
        _verify_ed25519(key["public_key"], cert["signature"], bytes.fromhex(cert["payload_hash"]))
    except Exception:
        cert_ok = False
        reasons.append("certificate_signature_invalid")

    if now < datetime.fromisoformat(cert["valid_from"].replace("Z","+00:00")):
        reasons.append("not_yet_valid")
    if now >= datetime.fromisoformat(cert["valid_until"].replace("Z","+00:00")):
        reasons.append("expired")
    if cert["status"] != "ACTIVE":
        reasons.append(f"status_{cert['status'].lower()}")
    if snapshot["state"] != "VERIFIED":
        reasons.append("current_snapshot_not_verified")

    valid = proof_ok and cert_ok and not reasons
    return {
        "valid": valid,
        "certificate_id": cert["id"],
        "serial_number": cert["serial_number"],
        "status": cert["status"],
        "subject_id": cert["subject_id"],
        "proof_signature_valid": proof_ok,
        "certificate_signature_valid": cert_ok,
        "checked_at": now.isoformat(),
        "reasons": reasons,
    }


@router.get("/verify/{serial_number}")
async def public_verify_certificate(serial_number: str) -> dict:
    """Machine-safe public verification surface for certificate serials."""
    rows = await supabase.rpc("trust_public_certificate_lookup", {"p_serial_number": serial_number})
    cert = rows[0] if isinstance(rows, list) and rows else None
    if not cert:
        raise HTTPException(404, "trust_certificate_not_found")

    now = datetime.now(timezone.utc)
    reasons: list[str] = []
    proof_ok = True
    certificate_ok = True

    proof = await supabase.select_one(
        "trust_proofs",
        "id,subject_id,state_snapshot_id,state,assurance_level,proof_hash",
        id=cert["proof_id"], subject_id=cert["subject_id"],
    )
    snapshot = await supabase.select_one(
        "trust_state_snapshots",
        "id,subject_id,state,assurance_level,state_hash,computed_at",
        id=cert["state_snapshot_id"], subject_id=cert["subject_id"],
    )
    current_state = await supabase.select_one(
        "trust_current_state",
        "subject_id,state,assurance_level,state_hash,computed_at",
        subject_id=cert["subject_id"],
    )
    stored_certificate = await supabase.select_one(
        "trust_certificates",
        "id,claims",
        id=cert["certificate_id"],
    )
    proof_sig = await supabase.select_one(
        "trust_proof_signatures",
        "id,proof_id,key_id,algorithm,signature,signed_payload_hash",
        id=cert["proof_signature_id"], proof_id=cert["proof_id"],
    )
    profile = await supabase.select_one(
        "trust_certificate_profiles",
        "id,profile_id,version,required_state,required_assurance,max_validity_seconds",
        id=cert["profile_id"],
    )
    issuer_key = await supabase.select_one(
        "trust_signing_keys",
        "key_id,algorithm,purpose,public_key,status,not_before,not_after",
        tenant_id=cert["tenant_id"], key_id=cert["issuer_key_id"],
    )

    try:
        if not proof or not proof_sig or proof_sig["signed_payload_hash"] != proof["proof_hash"]:
            raise ValueError("proof_binding_invalid")
        proof_key = await supabase.select_one(
            "trust_signing_keys",
            "key_id,algorithm,purpose,public_key,status,not_before,not_after",
            tenant_id=cert["tenant_id"], key_id=proof_sig["key_id"],
        )
        if not proof_key or proof_key["purpose"] != "TRUST_PROOF" or proof_key["algorithm"] != "ED25519":
            raise ValueError("proof_key_invalid")
        _verify_ed25519(proof_key["public_key"], proof_sig["signature"], bytes.fromhex(proof["proof_hash"]))
    except Exception:
        proof_ok = False
        reasons.append("proof_signature_invalid")

    try:
        if not snapshot or not profile or not issuer_key:
            raise ValueError("certificate_chain_incomplete")
        if issuer_key["purpose"] != "TRUST_CERTIFICATE" or issuer_key["algorithm"] != "ED25519":
            raise ValueError("issuer_key_invalid")
        payload = _certificate_payload(
            payload_version=cert["payload_version"],
            certificate_id=cert["serial_number"],
            serial_number=cert["serial_number"],
            profile_id=profile["profile_id"],
            profile_version=profile["version"],
            subject_id=cert["subject_id"],
            proof_id=cert["proof_id"],
            state_snapshot_id=cert["state_snapshot_id"],
            proof_signature_id=cert["proof_signature_id"],
            proof_hash=proof["proof_hash"],
            state_hash=snapshot["state_hash"],
            state=snapshot["state"],
            assurance_level=snapshot["assurance_level"],
            issuer_key_id=cert["issuer_key_id"],
            valid_from=datetime.fromisoformat(cert["valid_from"].replace("Z","+00:00")),
            valid_until=datetime.fromisoformat(cert["valid_until"].replace("Z","+00:00")),
            claims=(stored_certificate["claims"] if stored_certificate else {}),
        )
        expected_payload_hash = hashlib.sha256(payload).hexdigest()
        if expected_payload_hash != cert["payload_hash"]:
            raise ValueError("certificate_payload_hash_mismatch")
        _verify_ed25519(issuer_key["public_key"], cert["signature"], bytes.fromhex(cert["payload_hash"]))
    except Exception:
        certificate_ok = False
        reasons.append("certificate_signature_invalid")

    valid_from = datetime.fromisoformat(cert["valid_from"].replace("Z","+00:00"))
    valid_until = datetime.fromisoformat(cert["valid_until"].replace("Z","+00:00"))
    if now < valid_from:
        reasons.append("not_yet_valid")
    if now >= valid_until:
        reasons.append("expired")
    if cert["status"] != "ACTIVE":
        reasons.append(f"status_{cert['status'].lower()}")
    if not snapshot or snapshot["state"] != "VERIFIED":
        reasons.append("trust_state_not_verified")
    if not current_state or current_state["state"] != "VERIFIED":
        reasons.append("current_trust_state_not_verified")

    return {
        "valid": certificate_ok and proof_ok and not reasons,
        "serial_number": cert["serial_number"],
        "status": cert["status"],
        "issued_at": cert["issued_at"],
        "valid_from": cert["valid_from"],
        "valid_until": cert["valid_until"],
        "algorithm": cert["algorithm"],
        "payload_version": cert["payload_version"],
        "payload_hash": cert["payload_hash"],
        "proof_signature_valid": proof_ok,
        "certificate_signature_valid": certificate_ok,
        "checked_at": now.isoformat(),
        "reasons": reasons,
    }


class AssuranceProfileRequest(BaseModel):
    profile_id: str = Field(min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)
    display_name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=2000)
    min_state: str = "VERIFIED"
    min_assurance: str = "BASIC"
    max_evidence_age_seconds: int = Field(default=86400, ge=1, le=31536000)
    max_attestation_age_seconds: int = Field(default=86400, ge=1, le=31536000)
    require_verified_attestation: bool = True
    require_measurement: bool = True
    required_evidence_types: list[str] = Field(default_factory=list, max_length=64)
    allowed_subject_kinds: list[str] = Field(default_factory=list, max_length=32)


class TrustPolicyRequest(BaseModel):
    policy_id: str = Field(min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)
    display_name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=2000)
    assurance_profile_id: str
    certificate_profile_id: str | None = None
    decision: str = "CERTIFY"
    rules: dict[str, Any] = Field(default_factory=dict)


@router.post("/assurance-profiles")
async def create_assurance_profile(body: AssuranceProfileRequest, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    valid_states = {"REGISTERED","OBSERVED","ATTESTED","VERIFIED","DEGRADED","SUSPENDED","REVOKED","EXPIRED"}
    valid_assurance = {"NONE","BASIC","MEASURED","HARDWARE_BACKED","CRYPTOGRAPHIC"}
    if body.min_state not in valid_states or body.min_assurance not in valid_assurance:
        raise HTTPException(400, "invalid_trust_assurance_requirement")
    try:
        row = await supabase.insert("trust_assurance_profiles", {
            "tenant_id": principal.tenant_id,
            "profile_id": body.profile_id,
            "version": body.version,
            "display_name": body.display_name,
            "description": body.description,
            "min_state": body.min_state,
            "min_assurance": body.min_assurance,
            "max_evidence_age_seconds": body.max_evidence_age_seconds,
            "max_attestation_age_seconds": body.max_attestation_age_seconds,
            "require_verified_attestation": body.require_verified_attestation,
            "require_measurement": body.require_measurement,
            "required_evidence_types": body.required_evidence_types,
            "allowed_subject_kinds": body.allowed_subject_kinds,
            "status": "ACTIVE",
        })
    except Exception as exc:
        raise HTTPException(400, "trust_assurance_profile_rejected") from exc
    return {"assurance_profile": row}


@router.get("/assurance-profiles")
async def list_assurance_profiles(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    rows = await supabase.select("trust_assurance_profiles",
        "id,profile_id,version,display_name,description,min_state,min_assurance,max_evidence_age_seconds,max_attestation_age_seconds,require_verified_attestation,require_measurement,required_evidence_types,allowed_subject_kinds,status,created_at",
        tenant_id=principal.tenant_id)
    return {"assurance_profiles": rows}


@router.post("/policies")
async def create_trust_policy(body: TrustPolicyRequest, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    if body.decision not in {"ALLOW","CERTIFY","DENY"}:
        raise HTTPException(400, "invalid_trust_policy_decision")
    profile = await supabase.select_one("trust_assurance_profiles", "id,tenant_id,status", id=body.assurance_profile_id)
    if not profile or profile["status"] != "ACTIVE" or (profile["tenant_id"] not in (None, principal.tenant_id)):
        raise HTTPException(400, "trust_assurance_profile_not_available")
    try:
        row = await supabase.insert("trust_policies", {
            "tenant_id": principal.tenant_id,
            "policy_id": body.policy_id,
            "version": body.version,
            "display_name": body.display_name,
            "description": body.description,
            "assurance_profile_id": body.assurance_profile_id,
            "certificate_profile_id": body.certificate_profile_id,
            "decision": body.decision,
            "status": "ACTIVE",
            "rules": body.rules,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_policy_rejected") from exc
    return {"policy": row}


@router.get("/policies")
async def list_trust_policies(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    rows = await supabase.select("trust_policies",
        "id,policy_id,version,display_name,description,assurance_profile_id,certificate_profile_id,decision,status,rules,created_at",
        tenant_id=principal.tenant_id)
    return {"policies": rows}


@router.post("/policies/{policy_id}/evaluate/{subject_id}")
async def evaluate_trust_policy(policy_id: str, subject_id: str, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    policy = await supabase.select_one("trust_policies", "id,tenant_id,status", id=policy_id, tenant_id=principal.tenant_id)
    subject = await supabase.select_one("trust_subjects", "id,tenant_id", id=subject_id, tenant_id=principal.tenant_id)
    if not policy or policy["status"] != "ACTIVE":
        raise HTTPException(404, "trust_policy_not_found")
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    try:
        row = await supabase.rpc("trust_evaluate_policy", {
            "p_policy_id": policy_id,
            "p_subject_id": subject_id,
        })
    except Exception as exc:
        raise HTTPException(400, "trust_policy_evaluation_failed") from exc
    return {"evaluation": row}


@router.get("/subjects/{subject_id}/policy-evaluations")
async def list_policy_evaluations(subject_id: str, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    subject = await supabase.select_one("trust_subjects", "id,tenant_id", id=subject_id, tenant_id=principal.tenant_id)
    if not subject:
        raise HTTPException(404, "trust_subject_not_found")
    rows = await supabase.select("trust_policy_evaluations",
        "id,policy_id,subject_id,state_snapshot_id,decision,assurance,evidence_fresh,attestation_fresh,measurement_present,required_evidence_present,reasons,evaluation_hash,evaluated_at",
        tenant_id=principal.tenant_id, subject_id=subject_id)
    return {"evaluations": rows}
