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


class PublicKeyCeremonyIssueRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=200)
    purpose: str
    ttl_seconds: int = Field(default=600, ge=60, le=3600)


class PublicKeyCeremonyCompleteRequest(BaseModel):
    ceremony_id: str
    public_key: str
    signature: str


@router.post("/public/keys/ceremony")
async def issue_public_key_ceremony(
    request: PublicKeyCeremonyIssueRequest,
    principal: DeveloperPrincipal = Depends(_write),
):
    return await supabase.rpc(
        "trust_issue_public_key_ceremony",
        {"p_key_id": request.key_id, "p_purpose": request.purpose, "p_ttl_seconds": request.ttl_seconds},
    )


@router.post("/public/keys/ceremony/complete")
async def complete_public_key_ceremony(
    request: PublicKeyCeremonyCompleteRequest,
    principal: DeveloperPrincipal = Depends(_write),
):
    ceremony = await supabase.select_one("trust_public_key_ceremonies", "*", id=request.ceremony_id)
    if not ceremony:
        raise HTTPException(404, "ceremony_not_found")
    if ceremony.get("status") != "ISSUED":
        raise HTTPException(409, "ceremony_not_active")

    expires_at = ceremony.get("expires_at")
    if expires_at and datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")) <= datetime.now(timezone.utc):
        raise HTTPException(409, "ceremony_expired")

    challenge_hash = str(ceremony.get("challenge_hash") or "")
    if len(challenge_hash) != 64:
        raise HTTPException(500, "invalid_ceremony_challenge")

    try:
        _verify_ed25519(request.public_key, request.signature, bytes.fromhex(challenge_hash))
        public_key_bytes = _decode_crypto_bytes(request.public_key, 32)
        signature_bytes = _decode_crypto_bytes(request.signature, 64)
    except ValueError:
        raise HTTPException(400, "invalid_key_possession_signature")

    verification_hash = hashlib.sha256(
        bytes.fromhex(challenge_hash) + b"|" + public_key_bytes + b"|" + signature_bytes
    ).hexdigest()

    key_id = await supabase.rpc(
        "trust_activate_public_key_ceremony",
        {
            "p_ceremony_id": request.ceremony_id,
            "p_public_key": public_key_bytes.hex(),
            "p_verification_hash": verification_hash,
        },
    )
    return {"activated": True, "key_id": key_id, "verification_hash": verification_hash}


class EvidenceRequest(BaseModel):
    subject_id: str
    evidence_type: str
    source_type: str