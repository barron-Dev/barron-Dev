"""Canonical Ed25519 proof-of-possession verification for Global Integrity.

A valid signature proves key possession only, never hardware backing or device health.
"""
from __future__ import annotations
import base64
import hashlib
import json
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class GlobalIntegrityError(ValueError):
    pass

def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")

def principal_fingerprint(tenant_id: str, principal_kind: str, external_ref: str) -> str:
    if not tenant_id or not principal_kind or not external_ref:
        raise GlobalIntegrityError("principal identity is incomplete")
    return sha256_hex(f"cyclothone:principal:v1:{tenant_id}:{principal_kind}:{external_ref}".encode())

def device_fingerprint(tenant_id: str, device_ref: str) -> str:
    if not device_ref or len(device_ref)>256:
        raise GlobalIntegrityError("device reference is required")
    return sha256_hex(f"cyclothone:device:v1:{tenant_id}:{device_ref}".encode())

def context_hash(value: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(value))

def verify_ed25519(public_key_pem: str, signature_b64: str, payload: dict[str, Any]) -> bool:
    try:
        key=serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key,Ed25519PublicKey):
            raise GlobalIntegrityError("only Ed25519 public keys are supported in v1")
        signature=base64.b64decode(signature_b64,validate=True)
        if len(signature)!=64:
            raise GlobalIntegrityError("Ed25519 signature must be 64 bytes")
        key.verify(signature,canonical_json(payload))
        return True
    except InvalidSignature:
        return False
    except (ValueError,TypeError) as exc:
        raise GlobalIntegrityError("invalid public key or signature encoding") from exc

def public_key_fingerprint(public_key_pem: str) -> str:
    key=serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return sha256_hex(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
