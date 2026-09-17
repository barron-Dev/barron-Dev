from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from sentinel.storage.supabase_client import supabase


class ComplianceSigningError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ComplianceSignature:
    signature_b64: str
    kid: str


async def _load_private_key(kid: str) -> Ed25519PrivateKey:
    async def _key():
        return await (await supabase._ensure()).rpc("get_signing_key", {"p_kid": kid}).execute()

    response = await supabase._retry(_key, attempts=2)
    pem = response.data
    if isinstance(pem, list):
        pem = pem[0] if pem else None
    if not isinstance(pem, str) or not pem:
        raise ValueError("empty signing key")
    private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("configured signing key is not Ed25519")
    return private_key


async def _load_public_key(kid: str) -> Ed25519PublicKey:
    async def _key():
        return await (await supabase._ensure()).rpc("get_signing_public_key", {"p_kid": kid}).execute()

    response = await supabase._retry(_key, attempts=2)
    pem = response.data
    if isinstance(pem, list):
        pem = pem[0] if pem else None
    if not isinstance(pem, str) or not pem:
        raise ValueError("empty public signing key")
    public_key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("configured public signing key is not Ed25519")
    return public_key


async def sign_digest(digest_hex: str) -> ComplianceSignature:
    configured_kid = os.environ.get("SENTINEL_COMPLIANCE_SIGNING_KID")
    if configured_kid:
        row = await supabase.select_one("signing_keys", "kid,active", kid=configured_kid)
    else:
        async def _do():
            return await (await supabase._ensure()).table("signing_keys").select("kid,active").eq("active", True).limit(1).execute()
        rows = (await supabase._retry(_do, attempts=2)).data or []
        row = rows[0] if rows else None
    if not row or not row.get("active"):
        raise ComplianceSigningError("no active compliance signing key is provisioned")
    kid = str(row["kid"])
    try:
        private_key = await _load_private_key(kid)
        signature = private_key.sign(digest_hex.encode("ascii"))
        return ComplianceSignature(base64.b64encode(signature).decode("ascii"), kid)
    except Exception as exc:  # noqa: BLE001
        raise ComplianceSigningError("active compliance signing key could not be used") from exc


async def verify_digest_signature(digest_hex: str, signature_b64: str, kid: str) -> bool:
    """Verify a Sentinel signature using only the registered public key."""
    try:
        public_key = await _load_public_key(kid)
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, digest_hex.encode("ascii"))
        return True
    except Exception:  # noqa: BLE001
        return False
