from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

@dataclass(frozen=True)
class BundleEnvelope:
    bundle_id: str
    version: int
    kind: str
    schema_version: str
    issuer_tenant_id: str | None
    issuer_kid: str
    payload: dict[str, Any]
    payload_sha256: str
    signature: str
    signature_context: str
    expires_at: datetime

def canonical_payload(payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict):
        raise TypeError("bundle payload must be an object")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(payload)).hexdigest()

def signing_bytes(*, bundle_id: str, version: int, kind: str, schema_version: str,
                  issuer_tenant_id: str | None, issuer_kid: str, payload_hash: str,
                  expires_at: datetime) -> bytes:
    if version <= 0 or not bundle_id or not issuer_kid:
        raise ValueError("invalid signing metadata")
    if kind not in {"rule", "ioc", "model"}:
        raise ValueError("unsupported bundle kind")
    if not payload_hash or len(payload_hash) != 64:
        raise ValueError("invalid payload hash")
    exp = expires_at.astimezone(timezone.utc).isoformat()
    context = "cyclothone-immune-bundle-v1"
    return "\n".join([
        context, bundle_id, str(version), kind, schema_version,
        issuer_tenant_id or "global", issuer_kid, payload_hash, exp,
    ]).encode("utf-8")

def sign_bundle(private_key: Ed25519PrivateKey, **kwargs: Any) -> tuple[str, str]:
    data = signing_bytes(**kwargs)
    return (
        base64.b64encode(private_key.sign(data)).decode("ascii"),
        "cyclothone-immune-bundle-v1",
    )

def verify_bundle_signature(public_key: Ed25519PublicKey, signature_b64: str, **kwargs: Any) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise ValueError("invalid bundle signature encoding") from exc
    if len(signature) != 64:
        raise ValueError("invalid bundle signature length")
    try:
        public_key.verify(signature, signing_bytes(**kwargs))
    except Exception as exc:
        raise ValueError("bundle signature verification failed") from exc

def verify_envelope(envelope: BundleEnvelope, public_key: Ed25519PublicKey, now: datetime | None = None) -> None:
    if now is None:
        now = datetime.now(timezone.utc)
    if envelope.expires_at <= now:
        raise ValueError("bundle expired")
    if payload_sha256(envelope.payload) != envelope.payload_sha256:
        raise ValueError("bundle payload hash mismatch")
    if envelope.signature_context != "cyclothone-immune-bundle-v1":
        raise ValueError("unsupported signature context")
    verify_bundle_signature(
        public_key,
        envelope.signature,
        bundle_id=envelope.bundle_id,
        version=envelope.version,
        kind=envelope.kind,
        schema_version=envelope.schema_version,
        issuer_tenant_id=envelope.issuer_tenant_id,
        issuer_kid=envelope.issuer_kid,
        payload_hash=envelope.payload_sha256,
        expires_at=envelope.expires_at,
    )
