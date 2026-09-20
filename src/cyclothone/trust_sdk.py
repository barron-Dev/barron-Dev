"""Cyclothone Trust v1 verification SDK.

Performs local Ed25519 verification of a public certificate response.
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


def _key_current(
    key: Mapping[str, Any] | None,
    *,
    allow_retired: bool = False,
) -> bool:
    if not key or key.get("algorithm") != "ED25519":
        return False
    allowed_status = {"ACTIVE", "RETIRED"} if allow_retired else {"ACTIVE"}
    if key.get("status") not in allowed_status:
        return False
    now = datetime.now(timezone.utc)
    before = key.get("not_before")
    after = key.get("not_after")
    if before and datetime.fromisoformat(str(before).replace("Z", "+00:00")) > now:
        return False
    if after and datetime.fromisoformat(str(after).replace("Z", "+00:00")) <= now:
        return False
    return True


def verify_certificate_response(response: Mapping[str, Any]) -> dict[str, Any]:
    """Independently verify a Cyclothone public Trust response.

    The remote 'verified' boolean is not trusted.
    """
    reasons: list[str] = []
    certificate = response.get("certificate") or {}
    proof = response.get("proof") or {}
    attestation = response.get("attestation")
    ck = response.get("certificate_key")
    pk = response.get("proof_key")
    ak = response.get("attestation_key")
    authority_key = response.get("authority_key")
    authority_signature = certificate.get("authority_signature", "")
    authority_payload_hash = certificate.get("authority_signed_payload_hash", "")

    cert_ok = (
        _key_current(ck)
        and bool(certificate.get("payload_hash"))
        and verify_signature(
            ck["public_key"],
            certificate.get("signature", ""),
            certificate["payload_hash"],
        )
    )
    authority_ok = (
        _key_current(authority_key, allow_retired=True)
        and authority_key.get("purpose") == "TRUST_CERTIFICATE"
        and authority_payload_hash == certificate.get("payload_hash")
        and verify_signature(
            authority_key["public_key"],
            authority_signature,
            authority_payload_hash,
        )
    )
    proof_ok = (
        _key_current(pk)
        and proof.get("signed_payload_hash") == proof.get("proof_hash")
        and verify_signature(
            pk["public_key"],
            proof.get("signature", ""),
            proof.get("proof_hash", ""),
        )
    )
    att_ok = attestation is None
    if attestation:
        att_ok = (
            _key_current(ak)
            and attestation.get("signature_algorithm") == "ED25519"
            and verify_signature(
                ak["public_key"],
                attestation.get("signature", ""),
                attestation.get("signed_payload_hash", ""),
            )
        )

    if not cert_ok:
        reasons.append("certificate_signature_invalid")
    if not authority_ok:
        reasons.append("authority_signature_invalid")
    if not proof_ok:
        reasons.append("proof_signature_invalid")
    if not att_ok:
        reasons.append("attestation_signature_invalid")

    valid_until = certificate.get("valid_until")
    current = (
        certificate.get("status") == "ACTIVE"
        and bool(valid_until)
        and datetime.fromisoformat(str(valid_until).replace("Z", "+00:00")) > datetime.now(timezone.utc)
    )
    if not current:
        reasons.append("certificate_not_current")

    return {
        "verified": bool(cert_ok and authority_ok and proof_ok and att_ok and current and response.get("chain_verified")),
        "certificate_signature_verified": bool(cert_ok),
        "authority_signature_verified": bool(authority_ok),
        "proof_signature_verified": bool(proof_ok),
        "attestation_signature_verified": bool(att_ok),
        "chain_verified": bool(response.get("chain_verified")),
        "verification_hash": response.get("verification_hash"),
        "reasons": reasons,
    }


def verify_jwks(jwks: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a Cyclothone JWKS response without trusting remote status fields."""
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
    """Verify a certificate using a separately discovered JWKS key set.

    The certificate response's embedded public keys are deliberately ignored.
    Key IDs must resolve in the supplied JWKS and the JWKS keys must be valid
    Ed25519 signing keys.
    """
    discovered = verify_jwks(jwks)
    keys = discovered["valid"]
    reasons = list(discovered["reasons"])

    certificate = response.get("certificate") or {}
    proof = response.get("proof") or {}
    attestation = response.get("attestation")
    ck = keys.get(str((response.get("certificate_key") or {}).get("key_id", "")))
    pk = keys.get(str((response.get("proof_key") or {}).get("key_id", "")))
    ak = keys.get(str((response.get("attestation_key") or {}).get("key_id", ""))) if attestation else None
    authority_key = keys.get(str((response.get("authority_key") or {}).get("key_id", "")))

    def key_ok(key: Mapping[str, Any] | None, signature: str, payload_hash: str) -> bool:
        if not key or not signature or not payload_hash:
            return False
        try:
            return verify_signature(_jwks_public_key(key), signature, payload_hash)
        except (ValueError, TypeError):
            return False

    cert_ok = key_ok(ck, certificate.get("signature", ""), certificate.get("payload_hash", ""))
    authority_ok = (
        bool(authority_key)
        and authority_key.get("alg") == "EdDSA"
        and key_ok(authority_key, certificate.get("authority_signature", ""), certificate.get("authority_signed_payload_hash", ""))
        and certificate.get("authority_signed_payload_hash") == certificate.get("payload_hash")
    )
    proof_ok = (
        proof.get("signed_payload_hash") == proof.get("proof_hash")
        and key_ok(pk, proof.get("signature", ""), proof.get("proof_hash", ""))
    )
    att_ok = attestation is None
    if attestation:
        att_ok = key_ok(
            ak,
            attestation.get("signature", ""),
            attestation.get("signed_payload_hash", ""),
        )

    if not cert_ok:
        reasons.append("certificate_jwks_signature_invalid")
    if not authority_ok:
        reasons.append("authority_jwks_signature_invalid")
    if not proof_ok:
        reasons.append("proof_jwks_signature_invalid")
    if not att_ok:
        reasons.append("attestation_jwks_signature_invalid")

    valid_until = certificate.get("valid_until")
    current = (
        certificate.get("status") == "ACTIVE"
        and bool(valid_until)
        and datetime.fromisoformat(str(valid_until).replace("Z", "+00:00")) > datetime.now(timezone.utc)
    )
    if not current:
        reasons.append("certificate_not_current")

    return {
        "verified": bool(
            cert_ok
            and authority_ok
            and proof_ok
            and att_ok
            and current
            and response.get("chain_verified")
        ),
        "certificate_signature_verified": cert_ok,
        "authority_signature_verified": authority_ok,
        "proof_signature_verified": proof_ok,
        "attestation_signature_verified": att_ok,
        "chain_verified": bool(response.get("chain_verified")),
        "reasons": reasons,
    }
