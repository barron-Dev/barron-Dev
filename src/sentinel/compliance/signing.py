from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.storage.supabase_client import supabase

class ComplianceSigningError(RuntimeError):
    pass

@dataclass(frozen=True, slots=True)
class ComplianceSignature:
    signature_b64: str
    kid: str

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
    async def _key():
        return await (await supabase._ensure()).rpc("get_signing_key", {"p_kid": kid}).execute()
    try:
        response = await supabase._retry(_key, attempts=2)
        pem = response.data
        if isinstance(pem, list):
            pem = pem[0] if pem else None
        if not isinstance(pem, str) or not pem:
            raise ValueError("empty signing key")
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("configured signing key is not Ed25519")
        signature = private_key.sign(digest_hex.encode("ascii"))
        return ComplianceSignature(base64.b64encode(signature).decode("ascii"), kid)
    except Exception as exc:  # noqa: BLE001
        raise ComplianceSigningError("active compliance signing key could not be used") from exc
