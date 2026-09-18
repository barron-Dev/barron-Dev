from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import HTTPException, Request, status

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    device_id: str
    tenant_id: str
    cert_sha256: str


def _client_certificate(request: Request) -> x509.Certificate:
    tls = (request.scope.get("extensions") or {}).get("tls")
    if not isinstance(tls, dict):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mTLS connection required")
    if tls.get("client_cert_error"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="client certificate verification failed")
    chain = tls.get("client_cert_chain") or []
    if not chain:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="client certificate required")
    try:
        return x509.load_pem_x509_certificate(chain[0].encode("utf-8"))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid client certificate") from exc


async def get_device(request: Request) -> DeviceIdentity:
    certificate = _client_certificate(request)
    der = certificate.public_bytes(Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()

    async def lookup():
        client = await supabase._ensure()
        return await (
            client.table("devices")
            .select("id,tenant_id,mtls_cert_sha256,agent_enabled")
            .eq("mtls_cert_sha256", fingerprint)
            .eq("agent_enabled", True)
            .limit(1)
            .execute()
        )

    response = await supabase._retry(lookup, attempts=2)
    rows = response.data or []
    if not rows:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device certificate is not authorized")

    row = rows[0]
    return DeviceIdentity(
        device_id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        cert_sha256=fingerprint,
    )
