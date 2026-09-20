from __future__ import annotations

from datetime import datetime
import hashlib
import json
import hmac
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from cyclothone.compliance.trust_crypto import verify_ed25519_pem_signature, verify_ed25519_raw_signature
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
            "id,key_id,purpose,status,expires_at,challenge_hash",
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
        challenge_hash = ceremony.get("challenge_hash") if isinstance(ceremony, dict) else None
        if not ceremony_id or not challenge_hash:
            raise HTTPException(503, "trust_ceremony_issue_failed")

        try:
            challenge = bytes.fromhex(challenge_hash)
            possession_signature = private_key.sign(challenge)
            private_key.public_key().verify(possession_signature, challenge)
        except (ValueError, TypeError):
            raise HTTPException(503, "trust_authority_possession_proof_failed")

        activated = await supabase.rpc(
            "trust_activate_public_key_ceremony",
            {
                "p_ceremony_id": ceremony_id,
                "p_public_key": public_key,
                "p_verification_hash": challenge_hash,
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


@router.get("/certificates/{certificate_id}/cryptographic-verify")
async def cryptographic_verify_certificate(
    certificate_id: str,
    principal: DeveloperPrincipal = Depends(_read),
):
    """Perform real Ed25519 verification for every signature in a certificate chain."""
    certificate = await supabase.select_one(
        "trust_certificates",
        "id,tenant_id,subject_id,proof_id,proof_signature_id,payload_hash,signature,issuer_key_id,authority_key_id,authority_signature,authority_signed_payload_hash",
        id=certificate_id,
        tenant_id=principal.tenant_id,
    )
    if not certificate:
        raise HTTPException(404, "trust_certificate_not_found")

    proof = await supabase.select_one(
        "trust_proofs",
        "id,tenant_id,attestation_id,proof_hash",
        id=certificate["proof_id"],
        tenant_id=principal.tenant_id,
    )
    proof_signature = await supabase.select_one(
        "trust_proof_signatures",
        "id,tenant_id,key_id,algorithm,signature,signed_payload_hash",
        id=certificate["proof_signature_id"],
        tenant_id=principal.tenant_id,
    )

    checks: dict[str, bool] = {
        "certificate_signature": False,
        "proof_signature": False,
        "attestation_signature": False,
        "authority_signature": False,
    }
    reasons: list[str] = []

    issuer_key = await supabase.select_one(
        "trust_signing_keys",
        "key_id,purpose,algorithm,public_key,status,not_before,not_after",
        key_id=certificate["issuer_key_id"],
        tenant_id=principal.tenant_id,
    )
    if (
        issuer_key
        and issuer_key.get("purpose") == "TRUST_CERTIFICATE"
        and issuer_key.get("algorithm") == "ED25519"
        and issuer_key.get("public_key")
    ):
        checks["certificate_signature"] = verify_ed25519_pem_signature(
            issuer_key["public_key"],
            certificate["signature"],
            certificate["payload_hash"],
        )
    else:
        reasons.append("certificate_signing_key_unavailable")

    if proof and proof_signature:
        proof_key = await supabase.select_one(
            "trust_signing_keys",
            "key_id,purpose,algorithm,public_key,status,not_before,not_after",
            key_id=proof_signature["key_id"],
            tenant_id=principal.tenant_id,
        )
        if (
            proof_key
            and proof_key.get("purpose") == "TRUST_PROOF"
            and proof_key.get("algorithm") == "ED25519"
            and proof_signature.get("signed_payload_hash") == proof.get("proof_hash")
        ):
            checks["proof_signature"] = verify_ed25519_pem_signature(
                proof_key["public_key"],
                proof_signature["signature"],
                proof_signature["signed_payload_hash"],
            )
        else:
            reasons.append("proof_signing_key_or_binding_invalid")

    attestation = None
    attestation_signature = None
    if proof and proof.get("attestation_id"):
        attestation = await supabase.select_one(
            "trust_attestations",
            "id,tenant_id,signing_key_id,signature,signature_algorithm,signed_payload_hash",
            id=proof["attestation_id"],
            tenant_id=principal.tenant_id,
        )
        if attestation:
            attestation_signature = attestation
            attestation_key = await supabase.select_one(
                "trust_signing_keys",
                "key_id,purpose,algorithm,public_key,status,not_before,not_after",
                key_id=attestation["signing_key_id"],
                tenant_id=principal.tenant_id,
            )
            if (
                attestation_key
                and attestation_key.get("purpose") == "TRUST_ATTESTATION"
                and attestation_key.get("algorithm") == "ED25519"
                and attestation["signature_algorithm"] == "ED25519"
            ):
                checks["attestation_signature"] = verify_ed25519_pem_signature(
                    attestation_key["public_key"],
                    attestation["signature"],
                    attestation["signed_payload_hash"],
                )
            else:
                reasons.append("attestation_signing_key_unavailable")
        else:
            reasons.append("attestation_missing")

    authority_key = await supabase.select_one(
        "trust_public_key_directory",
        "key_id,purpose,algorithm,public_key,status,not_before,not_after",
        key_id=certificate["authority_key_id"],
        purpose="TRUST_AUTHORITY",
    )
    if (
        authority_key
        and authority_key.get("algorithm") == "ED25519"
        and certificate.get("authority_signed_payload_hash") == certificate.get("payload_hash")
        and certificate.get("authority_signature")
    ):
        checks["authority_signature"] = verify_ed25519_raw_signature(
            authority_key["public_key"],
            certificate["authority_signature"],
            certificate["authority_signed_payload_hash"],
        )
    else:
        reasons.append("authority_key_or_binding_invalid")

    cryptographic_verified = all(checks.values())
    if not cryptographic_verified:
        reasons.extend(name + "_verification_failed" for name, passed in checks.items() if not passed)

    reasons = sorted(set(reasons))
    verification_material = json.dumps(
        {
            "certificate_id": certificate_id,
            "checks": checks,
            "reasons": reasons,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    verification_hash = hashlib.sha256(verification_material).hexdigest()
    try:
        await supabase.rpc(
            "trust_record_certificate_cryptographic_verification",
            {
                "p_tenant_id": principal.tenant_id,
                "p_certificate_id": certificate_id,
                "p_verified": cryptographic_verified,
                "p_verification_hash": verification_hash,
                "p_reason": ";".join(reasons) if reasons else None,
            },
        )
    except Exception as exc:
        raise HTTPException(503, "trust_verification_recording_failed") from exc

    return {
        "certificate_id": certificate_id,
        "cryptographic_verified": cryptographic_verified,
        "checks": checks,
        "reasons": reasons,
        "verification_hash": verification_hash,
    }
