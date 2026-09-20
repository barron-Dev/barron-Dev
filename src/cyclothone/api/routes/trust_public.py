from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

from fastapi import APIRouter, HTTPException

from cyclothone.storage.supabase_client import supabase
from cyclothone.api.routes.trust import _verify_ed25519

router = APIRouter(prefix="/trust/public", tags=["public-trust-verification"])


def _now():
    return datetime.now(timezone.utc)


def _dt(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


def _valid_key(key):
    if not key or key.get("algorithm") != "ED25519" or key.get("status") != "ACTIVE" or not key.get("public_key"):
        return False
    return (
        (not key.get("not_before") or _dt(key["not_before"]) <= _now())
        and (not key.get("not_after") or _dt(key["not_after"]) > _now())
    )


def _verify(key, signature, payload_hash):
    if not _valid_key(key) or not signature or not payload_hash or len(payload_hash) != 64:
        return False
    try:
        _verify_ed25519(key["public_key"], signature, bytes.fromhex(payload_hash))
        return True
    except (ValueError, TypeError):
        return False


def _public_key_view(key):
    if not key:
        return None
    return {
        "key_id": key.get("key_id"),
        "algorithm": key.get("algorithm"),
        "public_key": key.get("public_key"),
        "status": key.get("status"),
        "not_before": key.get("not_before"),
        "not_after": key.get("not_after"),
    }


@router.get("/certificates/{serial_number}")
async def verify_public_certificate(serial_number: str):
    material = await supabase.rpc(
        "trust_public_certificate_material",
        {"p_serial_number": serial_number},
    )
    if not material:
        raise HTTPException(status_code=404, detail="certificate_not_found")

    certificate = material.get("certificate") or {}
    proof = material.get("proof") or {}
    proof_signature = material.get("proof_signature") or {}
    certificate_key = material.get("certificate_key")
    proof_key = material.get("proof_key")
    attestation = material.get("attestation")
    attestation_key = material.get("attestation_key")

    reasons: list[str] = []

    certificate_signature_verified = (
        certificate.get("algorithm") == "ED25519"
        and _verify(certificate_key, certificate.get("signature"), certificate.get("payload_hash"))
    )
    proof_signature_verified = (
        bool(proof)
        and bool(proof_signature)
        and proof_signature.get("algorithm") == "ED25519"
        and proof_signature.get("signed_payload_hash") == proof.get("proof_hash")
        and _verify(proof_key, proof_signature.get("signature"), proof.get("proof_hash"))
    )
    attestation_signature_verified = not proof.get("attestation_id")
    if attestation:
        attestation_signature_verified = (
            attestation.get("signature_algorithm") == "ED25519"
            and bool(attestation.get("signed_payload_hash"))
            and _verify(attestation_key, attestation.get("signature"), attestation.get("signed_payload_hash"))
        )

    if not certificate_signature_verified:
        reasons.append("certificate_signature_invalid")
    if not proof_signature_verified:
        reasons.append("proof_signature_invalid")
    if not attestation_signature_verified:
        reasons.append("attestation_signature_invalid")

    now = _now()
    current = (
        certificate.get("status") == "ACTIVE"
        and _dt(certificate.get("valid_from")) <= now
        and _dt(certificate.get("valid_until")) > now
    )
    if not current:
        reasons.append("certificate_not_current")

    crypto_verified = certificate_signature_verified and proof_signature_verified and attestation_signature_verified and current

    chain = (
        await supabase.rpc("trust_verify_certificate_chain", {"p_certificate_id": certificate["id"]})
        if crypto_verified
        else {"verified": False, "reasons": reasons}
    )
    chain_verified = bool(chain and chain.get("verified"))
    if crypto_verified and not chain_verified:
        reasons.extend(reason for reason in (chain.get("reasons") or []) if reason not in reasons)

    verified = crypto_verified and chain_verified

    verification_hash = hashlib.sha256(
        json.dumps(
            {
                "certificate_id": certificate.get("id"),
                "certificate_payload_hash": certificate.get("payload_hash"),
                "proof_hash": proof.get("proof_hash"),
                "attestation_hash": attestation.get("attestation_hash") if attestation else None,
                "crypto_verified": crypto_verified,
                "chain_verified": chain_verified,
                "verified": verified,
                "reasons": reasons,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()

    if not crypto_verified:
        await supabase.rpc(
            "trust_commit_public_certificate_verification",
            {
                "p_certificate_id": certificate["id"],
                "p_status": "FAILED",
                "p_verification_hash": verification_hash,
                "p_reason": ",".join(reasons),
            },
        )

    return {
        "verification_protocol": "cyclothone-trust-v1",
        "verified": verified,
        "serial_number": serial_number,
        "certificate_id": certificate["id"],
        "algorithm": "ED25519",
        "certificate_signature_verified": certificate_signature_verified,
        "proof_signature_verified": proof_signature_verified,
        "attestation_signature_verified": attestation_signature_verified,
        "chain_verified": chain_verified,
        "certificate_key": _public_key_view(certificate_key),
        "proof_key": _public_key_view(proof_key),
        "attestation_key": _public_key_view(attestation_key),
        "certificate": {
            "payload_hash": certificate.get("payload_hash"),
            "signature": certificate.get("signature"),
            "valid_from": certificate.get("valid_from"),
            "valid_until": certificate.get("valid_until"),
            "status": certificate.get("status"),
        },
        "proof": {
            "proof_hash": proof.get("proof_hash"),
            "signature": proof_signature.get("signature"),
            "signed_payload_hash": proof_signature.get("signed_payload_hash"),
        },
        "attestation": (
            {
                "attestation_hash": attestation.get("attestation_hash"),
                "signature": attestation.get("signature"),
                "signed_payload_hash": attestation.get("signed_payload_hash"),
                "signature_algorithm": attestation.get("signature_algorithm"),
            }
            if attestation
            else None
        ),
        "valid_from": certificate.get("valid_from"),
        "valid_until": certificate.get("valid_until"),
        "verification_hash": verification_hash,
        "reasons": reasons,
    }
