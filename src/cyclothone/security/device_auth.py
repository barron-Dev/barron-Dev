from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

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

    raw = chain[0]
    try:
        if isinstance(raw, bytes):
            return x509.load_pem_x509_certificate(raw)
        if isinstance(raw, str):
            return x509.load_pem_x509_certificate(raw.encode("utf-8"))
    except (TypeError, ValueError):
        pass
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid client certificate")


async def get_device(request: Request) -> DeviceIdentity:
    certificate = _client_certificate(request)
    fingerprint = hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()
    now = datetime.now(timezone.utc)

    async def lookup():
        client = await supabase._ensure()
        return await (
            client.table("devices")
            .select("id,tenant_id,status,cert_fingerprint,certificate_not_before,certificate_not_after")
            .eq("cert_fingerprint", fingerprint)
            .eq("status", "active")
            .limit(1)
            .execute()
        )

    response = await supabase._retry(lookup, attempts=2)
    rows = response.data or []
    if not rows:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device certificate is not authorized")

    row = rows[0]
    not_before = row.get("certificate_not_before")
    not_after = row.get("certificate_not_after")
    if not not_before or not not_after:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device certificate validity is not registered")

    try:
        before = datetime.fromisoformat(str(not_before).replace("Z", "+00:00"))
        after = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device certificate validity is invalid") from exc

    if before > now or after < now:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device certificate is expired or not yet valid")

    return DeviceIdentity(device_id=str(row["id"]), tenant_id=str(row["tenant_id"]), cert_sha256=fingerprint)
