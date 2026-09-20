from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/certificates/issuance-preflight")
async def certificate_issuance_preflight(_: DeveloperPrincipal = Depends(_read)):
    checks = {
        "authority_key": False,
        "certificate_signing_path": False,
        "policy_engine": False,
    }
    authority = {"status": "UNKNOWN", "active_key_count": 0}
    errors: list[str] = []

    try:
        keys = await supabase.select(
            "trust_public_key_directory",
            "key_id,status,not_before,not_after",
            purpose="TRUST_CERTIFICATE",
            status="ACTIVE",
        )
        authority["active_key_count"] = len(keys)
        authority["status"] = "AVAILABLE" if keys else "NOT_CONFIGURED"
        checks["authority_key"] = bool(keys)

        functions = await supabase.rpc("trust_re_evaluation_queue_stats", {})
        checks["certificate_signing_path"] = functions is not None

        policies = await supabase.select(
            "trust_policies",
            "id,status",
            status="ACTIVE",
        )
        checks["policy_engine"] = policies is not None
    except Exception:
        errors.append("preflight_dependency_unavailable")

    issuance_ready = all(checks.values())

    return {
        "status": "READY" if issuance_ready else "NOT_READY",
        "capability": "CERTIFICATE_ISSUANCE",
        "issuance_ready": issuance_ready,
        "checks": checks,
        "authority": authority,
        "blocking_reasons": (
            [key for key, value in checks.items() if not value]
            + errors
        ),
    }


class CertificateIssuancePreflightRequest(BaseModel):
    subject_id: str
    profile_id: str
    state_snapshot_id: str
    proof_id: str
    proof_signature_id: str
    issuer_key_id: str = Field(min_length=1, max_length=256)
    trust_policy_id: str
    policy_evaluation_id: str
    valid_from: datetime
    valid_until: datetime
    serial_number: str | None = Field(default=None, min_length=16, max_length=128)
    payload_hash: str | None = Field(default=None, min_length=64, max_length=64)
    signature: str | None = Field(default=None, min_length=32)
    authority_key_id: str | None = Field(default=None, min_length=1, max_length=256)
    authority_signature: str | None = None
    authority_signed_payload_hash: str | None = Field(default=None, min_length=64, max_length=64)


@router.post("/certificates/issuance-preflight")
async def subject_certificate_issuance_preflight(
    request: CertificateIssuancePreflightRequest,
    principal: DeveloperPrincipal = Depends(_read),
):
    try:
        result = await supabase.rpc(
            "trust_certificate_issuance_preflight",
            {
                "p_tenant_id": principal.tenant_id,
                "p_subject_id": request.subject_id,
                "p_profile_id": request.profile_id,
                "p_state_snapshot_id": request.state_snapshot_id,
                "p_proof_id": request.proof_id,
                "p_proof_signature_id": request.proof_signature_id,
                "p_issuer_key_id": request.issuer_key_id,
                "p_trust_policy_id": request.trust_policy_id,
                "p_policy_evaluation_id": request.policy_evaluation_id,
                "p_valid_from": request.valid_from,
                "p_valid_until": request.valid_until,
                "p_serial_number": request.serial_number,
                "p_payload_hash": request.payload_hash,
                "p_signature": request.signature,
                "p_authority_key_id": request.authority_key_id,
                "p_authority_signature": request.authority_signature,
                "p_authority_signed_payload_hash": request.authority_signed_payload_hash,
            },
        )
    except Exception as exc:
        message = str(exc)
        if "service_role_required" in message:
            raise HTTPException(500, "trust_preflight_configuration_error") from exc
        raise HTTPException(503, "trust_preflight_unavailable") from exc

    if not isinstance(result, dict):
        raise HTTPException(500, "invalid_trust_preflight_response")
    return result
