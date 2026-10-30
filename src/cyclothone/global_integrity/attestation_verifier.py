"""Verification of detached assertions from pinned platform-attestation verifiers.

This module verifies the verifier's signature and statement binding. Platform certificate
chains/nonce semantics are validated by the separately operated platform verifier before it
is allowed to sign. No client-supplied assertion can self-promote a device.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cyclothone.global_integrity.crypto import GlobalIntegrityError, canonical_json, sha256_hex

_FORMATS = {
    ("android", "android_key"): "hardware_attested",
    ("android", "play_integrity"): "hardware_attested",
    ("ios", "apple_app_attest"): "hardware_attested",
    ("windows", "tpm2"): "hardware_attested",
    ("macos", "tpm2"): "hardware_attested",
    ("linux", "tpm2"): "hardware_attested",
    ("linux", "workload"): "workload_attested",
    ("server", "workload"): "workload_attested",
}
_REQUIRED = {
    "schema", "verifier_key_id", "policy_version", "tenant_id", "principal_id",
    "device_id", "device_fingerprint", "public_key_fingerprint", "challenge_id",
    "challenge_nonce", "context_sha256", "platform", "attestation_format",
    "assurance_level", "evidence_sha256", "issued_at", "valid_until",
}


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise GlobalIntegrityError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GlobalIntegrityError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise GlobalIntegrityError(f"{field} must include timezone")
    return parsed.astimezone(UTC)


def verify_verifier_assertion(
    assertion: dict[str, Any], signature_b64: str, verifier_public_key_pem: str,
    *, now: datetime | None = None,
) -> tuple[str, str]:
    if not isinstance(assertion, dict) or set(assertion) != _REQUIRED:
        raise GlobalIntegrityError("attestation assertion schema mismatch")
    if assertion["schema"] != "cyclothone.platform-attestation.v1":
        raise GlobalIntegrityError("unsupported attestation assertion schema")
    for field in ("tenant_id", "principal_id", "device_id", "challenge_id", "verifier_key_id",
                  "policy_version", "platform", "attestation_format", "assurance_level"):
        if not isinstance(assertion[field], str) or not assertion[field]:
            raise GlobalIntegrityError(f"{field} is required")
    for field in ("device_fingerprint", "public_key_fingerprint", "context_sha256", "evidence_sha256"):
        value = assertion[field]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise GlobalIntegrityError(f"{field} must be a lowercase SHA-256 digest")
    nonce = assertion["challenge_nonce"]
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
        raise GlobalIntegrityError("challenge_nonce must be a 32-byte hex nonce")
    expected_assurance = _FORMATS.get((assertion["platform"], assertion["attestation_format"]))
    if expected_assurance is None or assertion["assurance_level"] != expected_assurance:
        raise GlobalIntegrityError("platform attestation format and assurance do not match policy")
    issued = _time(assertion["issued_at"], "issued_at")
    valid_until = _time(assertion["valid_until"], "valid_until")
    current = now or datetime.now(UTC)
    if issued > current + timedelta(seconds=60) or issued < current - timedelta(minutes=5):
        raise GlobalIntegrityError("verifier assertion is outside allowed clock skew")
    if valid_until <= current or valid_until > current + timedelta(hours=24):
        raise GlobalIntegrityError("verifier assertion validity is outside policy")
    try:
        key = serialization.load_pem_public_key(verifier_public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise GlobalIntegrityError("pinned verifier key must be Ed25519")
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            raise GlobalIntegrityError("verifier signature must be 64 bytes")
        key.verify(signature, canonical_json(assertion))
    except InvalidSignature as exc:
        raise GlobalIntegrityError("verifier assertion signature invalid") from exc
    except (ValueError, TypeError) as exc:
        raise GlobalIntegrityError("verifier key or signature encoding invalid") from exc
    return sha256_hex(canonical_json(assertion)), valid_until.isoformat()
