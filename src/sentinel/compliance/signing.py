from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ComplianceSigningError(RuntimeError):
    pass

@dataclass(frozen=True, slots=True)
class ComplianceSignature:
    signature_b64: str
    kid: str


def sign_digest(digest_hex: str) -> ComplianceSignature:
    encoded = os.environ.get("SENTINEL_COMPLIANCE_SIGNING_KEY_B64")
    kid = os.environ.get("SENTINEL_COMPLIANCE_SIGNING_KID")
    if not encoded or not kid:
        raise ComplianceSigningError("compliance signing key and KID must be provisioned")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        signature = Ed25519PrivateKey.from_private_bytes(raw).sign(digest_hex.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise ComplianceSigningError("invalid compliance signing key configuration") from exc
    return ComplianceSignature(base64.b64encode(signature).decode("ascii"), kid)
