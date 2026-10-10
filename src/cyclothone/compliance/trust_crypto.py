from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class TrustCryptographicVerificationError(ValueError):
    pass


def _hash_message(value: str) -> bytes:
    if len(value) != 64:
        raise TrustCryptographicVerificationError("invalid_signed_payload_hash")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise TrustCryptographicVerificationError("invalid_signed_payload_hash") from exc
    return value.encode("ascii")


def verify_ed25519_pem_signature(
    public_key_pem: str,
    signature_b64: str,
    signed_payload_hash: str,
) -> bool:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            return False
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            return False
        key.verify(signature, _hash_message(signed_payload_hash))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def verify_ed25519_raw_signature(
    public_key_hex: str,
    signature_hex: str,
    signed_payload_hash: str,
) -> bool:
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            _hash_message(signed_payload_hash),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
