"""Cyclothone Trust v1 verification SDK.

Performs independent Ed25519 verification of public Trust certificates and
uses the public Cyclothone authority JWKS for authority endorsement.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _bytes(value: str, size: int) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raw = base64.b64decode(value, validate=True)
    if len(raw) != size:
        raise ValueError("invalid_cryptographic_length")
    return raw


def verify_signature(public_key: str, signature: str, payload_hash: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(_bytes(public_key, 32)).verify(
            _bytes(signature, 64),
            bytes.fromhex(payload_hash),
        )
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False


def _key_current(key: Mapping[str, Any] | None) -> bool:
    if not key or key.get("algorithm") != "ED25519" or key.get("status") not in {"ACTIVE", "RETIRED"}:
        return False
    now = datetime.now(timezone.utc)
    before = key.get("not_before")
    after = key.get("not_after")
    if before and datetime.fromisoformat(str(before).replace("Z", "+00:00")) > now:
        return False
    if after and datetime.fromisoformat(str(after).replace("Z", "+00:00")) <= now:
        return False
    return True


def _certificate_current(certificate: Mapping[str, Any]) -> bool:
    now = datetime.now(timezone.utc)
    start = certificate.get("valid_from")
    end = certificate.get("valid_until")
    return (
        certificate.get("status") == "ACTIVE"
        and bool(start)
        and bool(end)
        and datetime.fromisoformat(str(start).replace("Z", "+00:00")) <= now
        and datetime.fromisoformat(str(end).replace("Z", "+00:00")) > now
    )


def verify_certificate_response(response: Mapping[str, Any]) -> dict[str, Any]:
    """Independently verify a Cyclothone public Trust response.

    The remote 'verified' boolean is never trusted.
    """
    reasons: list[str] = []
    certificate = response.get("certificate") or {}
    proof = response.get("proof") or {}
    attestation = response.get("attestation")
    ck = response.get("certificate_key")
    authority_key = response.get("authority_key")
    pk = response.get("proof_key")
    ak = response.get("attestation_key")

    cert_ok = _key_current(ck) and verify_signature(
        ck["public_key"], certificate.get("signature", ""), certificate.get("payload_hash", "")
    )
    authority_ok = (
        _key_current(authority_key)
        and certificate.get("authority_signed_payload_hash") == certificate.get("payload_hash")
        and verify_signature(
            authority_key["public_key"],
            certificate.get("authority_signature", ""),
            certificate.get("authority_signed_payload_hash", ""),
        )
    )
    proof_ok = (
        _key_current(pk)
        and proof.get("signed_payload_hash") == proof.get("proof_hash")
        and verify_signature(pk["public_key"], proof.get("signature", ""), proof.get("proof_hash", ""))
    )
    att_ok = attestation is None
    if attestation:
        att_ok = (
            _key_current(ak)
            and attestation.get("signature_algorithm") == "ED25519"
            and verify_signature(ak["public_key"], attestation.get("signature", ""), attestation.get("signed_payload_hash", ""))
        )

    if not cert_ok:
        reasons.append("certificate_signature_invalid")
    if not authority_ok:
        reasons.append("authority_signature_invalid")
    if not proof_ok:
        reasons.append("proof_signature_invalid")
    if not att_ok:
        reasons.append("attestation_signature_invalid")

    current = _certificate_current(certificate)
    if not current:
        reasons.append("certificate_not_current")

    return {
        "verified": bool(cert_ok and authority_ok and proof_ok and att_ok and current and response.get("chain_verified")),
        "certificate_signature_verified": cert_ok,
        "authority_signature_verified": authority_ok,
        "proof_signature_verified": proof_ok,
        "attestation_signature_verified": att_ok,
        "chain_verified": bool(response.get("chain_verified")),
        "verification_hash": response.get("verification_hash"),
        "reasons": reasons,
    }


def verify_jwks(jwks: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a Cyclothone authority JWKS response."""
    keys = jwks.get("keys") or []
    valid: dict[str, Mapping[str, Any]] = {}
    reasons: list[str] = []
    for key in keys:
        try:
            if (
                key.get("kty") != "OKP"
                or key.get("crv") != "Ed25519"
                or key.get("alg") != "EdDSA"
                or key.get("use") != "sig"
                or not key.get("kid")
            ):
                reasons.append(f"invalid_key:{key.get('kid','unknown')}")
                continue
            padded = str(key["x"]) + "=" * (-len(str(key["x"])) % 4)
            raw = base64.urlsafe_b64decode(padded)
            if len(raw) != 32:
                raise ValueError("invalid_key_length")
            valid[str(key["kid"])] = key
        except (ValueError, TypeError):
            reasons.append(f"invalid_key:{key.get('kid','unknown')}")
    return {"valid": valid, "reasons": reasons, "count": len(valid)}


def _jwks_public_key(key: Mapping[str, Any]) -> str:
    padded = str(key["x"]) + "=" * (-len(str(key["x"])) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise ValueError("invalid_jwks_public_key")
    return raw.hex()


def verify_certificate_response_with_jwks(
    response: Mapping[str, Any],
    jwks: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a Trust certificate with separately discovered Cyclothone authority keys.

    The authority endorsement MUST resolve by key ID in the supplied JWKS.
    Tenant-bound certificate/proof/attestation keys are verified from the
    certificate response because they are scoped signing material rather than
    globally published Cyclothone authority keys.
    """
    discovered = verify_jwks(jwks)
    keys = discovered["valid"]
    reasons = list(discovered["reasons"])

    certificate = response.get("certificate") or {}
    proof = response.get("proof") or {}
    attestation = response.get("attestation")
    ck = response.get("certificate_key")
    authority_ref = response.get("authority_key") or {}
    pk = response.get("proof_key")
    ak = response.get("attestation_key")

    authority_discovered = keys.get(str(authority_ref.get("key_id", "")))
    authority_public_key = _jwks_public_key(authority_discovered) if authority_discovered else None

    cert_ok = _key_current(ck) and verify_signature(
        ck["public_key"], certificate.get("signature", ""), certificate.get("payload_hash", "")
    )
    authority_ok = (
        bool(authority_public_key)
        and certificate.get("authority_signed_payload_hash") == certificate.get("payload_hash")
        and verify_signature(
            authority_public_key,
            certificate.get("authority_signature", ""),
            certificate.get("authority_signed_payload_hash", ""),
        )
    )
    proof_ok = (
        _key_current(pk)
        and proof.get("signed_payload_hash") == proof.get("proof_hash")
        and verify_signature(pk["public_key"], proof.get("signature", ""), proof.get("proof_hash", ""))
    )
    att_ok = attestation is None
    if attestation:
        att_ok = (
            _key_current(ak)
            and attestation.get("signature_algorithm") == "ED25519"
            and verify_signature(
                ak["public_key"], attestation.get("signature", ""), attestation.get("signed_payload_hash", "")
            )
        )

    if not cert_ok:
        reasons.append("certificate_signature_invalid")
    if not authority_ok:
        reasons.append("authority_jwks_signature_invalid")
    if not proof_ok:
        reasons.append("proof_signature_invalid")
    if not att_ok:
        reasons.append("attestation_signature_invalid")

    current = _certificate_current(certificate)
    if not current:
        reasons.append("certificate_not_current")

    return {
        "verified": bool(cert_ok and authority_ok and proof_ok and att_ok and current and response.get("chain_verified")),
        "certificate_signature_verified": cert_ok,
        "authority_signature_verified": authority_ok,
        "proof_signature_verified": proof_ok,
        "attestation_signature_verified": att_ok,
        "chain_verified": bool(response.get("chain_verified")),
        "reasons": reasons,
    }
