from __future__ import annotations

from datetime import datetime
import hmac
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Header, HTTPException
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
            purpose="TRUST_AUTHORITY",
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


@router.post("/authority/activate", include_in_schema=False)
async def activate_trust_authority(
    authorization: str | None = Header(None),
):
    """
    One-time operational activation of the pre-provisioned TRUST_AUTHORITY key.
    The private key never leaves Railway and is never returned to the caller.
    """
    expected = os.getenv("CYCLOTHONE_TRUST_ACTIVATION_TOKEN")
    if not expected or not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(404, "not_found")
    supplied = authorization[7:].strip()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(404, "not_found")

    key_id = os.getenv("CYCLOTHONE_TRUST_AUTHORITY_KEY_ID")
    private_hex = os.getenv("CYCLOTHONE_TRUST_AUTHORITY_KEY_ED25519_PRIVATE_HEX")
    if not key_id or not private_hex or len(private_hex) != 64:
        raise HTTPException(503, "trust_authority_configuration_error")

    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
        public_key = private_key.public_key().public_bytes_raw().hex()
        verification_hash = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
    except (ValueError, TypeError):
        raise HTTPException(503, "trust_authority_key_invalid")

    try:
        active = await supabase.select(
            "trust_public_key_directory",
            "id,key_id,status",
            purpose="TRUST_AUTHORITY",
            status="ACTIVE",
        )
        if active:
            raise HTTPException(409, "trust_authority_already_active")

        ceremonies = await supabase.select(
            "trust_public_key_ceremonies",
            "id,key_id,purpose,status,expires_at",
            key_id=key_id,
            purpose="TRUST_AUTHORITY",
            status="ISSUED",
        )
        now = datetime.now().astimezone()
        usable = [
            c for c in ceremonies
            if c.get("expires_at") and datetime.fromisoformat(c["expires_at"].replace("Z", "+00:00")) > now
        ]
        if usable:
            ceremony = max(usable, key=lambda x: x["expires_at"])
        else:
            ceremony = await supabase.rpc(
                "trust_issue_public_key_ceremony",
                {"p_key_id": key_id, "p_purpose": "TRUST_AUTHORITY", "p_ttl_seconds": 600},
            )

        ceremony_id = ceremony.get("id") if isinstance(ceremony, dict) else ceremony.get("ceremony_id")
        if not ceremony_id:
            raise HTTPException(503, "trust_ceremony_issue_failed")

        activated = await supabase.rpc(
            "trust_activate_public_key_ceremony",
            {
                "p_ceremony_id": ceremony_id,
                "p_public_key": public_key,
                "p_verification_hash": verification_hash,
            },
        )
        if activated != key_id:
            raise HTTPException(503, "trust_authority_activation_failed")
        return {"status": "ACTIVE", "purpose": "TRUST_AUTHORITY", "key_id": key_id}
    except HTTPException:
        raise
    except Exception as exc:
        message = str(exc)
        if "service_role_required" in message:
            raise HTTPException(503, "trust_service_role_configuration_error") from exc
        raise HTTPException(503, "trust_authority_activation_failed") from exc
