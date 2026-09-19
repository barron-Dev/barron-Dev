from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import base64
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _decode_crypto_bytes(value: str, expected_len: int) -> bytes:
    raw = value.strip()
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ValueError("invalid_cryptographic_encoding") from exc
    if len(decoded) != expected_len:
        raise ValueError("invalid_cryptographic_length")
    return decoded


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> None:
    try:
        key_bytes = _decode_crypto_bytes(public_key, 32)
        signature_bytes = _decode_crypto_bytes(signature, 64)
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, message)
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("invalid_ed25519_signature") from exc


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


def _write(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:write",))
    return principal


class EvidenceRequest(BaseModel):
    subject_id: str
    evidence_type: str
    source_type: str