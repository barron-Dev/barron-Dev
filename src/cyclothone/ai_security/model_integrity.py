"""Fail-closed local model artifact verification for AI Security.

The expected digest and signature must come from a separately trusted registry. This
module never fetches registry data or model weights and never treats a digest alone as
proof of publisher identity.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ModelIntegrityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ModelManifest:
    model_id: str
    version: str
    artifact_sha256: str
    signer_key_id: str
    signature_hex: str
    runtime: str
    runtime_version: str

    def signed_payload(self) -> bytes:
        if not self.model_id or len(self.model_id) > 200 or not self.version:
            raise ModelIntegrityError("invalid_model_identity")
        if not _SHA256.fullmatch(self.artifact_sha256):
            raise ModelIntegrityError("invalid_artifact_sha256")
        if not self.signer_key_id or len(self.signer_key_id) > 200:
            raise ModelIntegrityError("invalid_signer_key_id")
        payload = {"schema":"cyclothone.model-manifest.v1","model_id":self.model_id,
                   "version":self.version,"artifact_sha256":self.artifact_sha256,
                   "signer_key_id":self.signer_key_id,"runtime":self.runtime,
                   "runtime_version":self.runtime_version}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode()


def sha256_file(path: str | Path, *, max_bytes: int = 20_000_000_000) -> tuple[str, int]:
    target = Path(path).expanduser()
    if not target.is_file():
        raise ModelIntegrityError("model_artifact_not_a_file")
    digest, total = hashlib.sha256(), 0
    with target.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ModelIntegrityError("model_artifact_exceeds_size_limit")
            digest.update(chunk)
    if total == 0:
        raise ModelIntegrityError("empty_model_artifact")
    return digest.hexdigest(), total


def verify_model_artifact(path: str | Path, manifest: ModelManifest, *,
                          trusted_signers: Mapping[str, Ed25519PublicKey],
                          max_bytes: int = 20_000_000_000) -> dict:
    signer = trusted_signers.get(manifest.signer_key_id)
    if signer is None:
        raise ModelIntegrityError("manifest_signer_not_trusted")
    try:
        signature = bytes.fromhex(manifest.signature_hex)
        signer.verify(signature, manifest.signed_payload())
    except (ValueError, InvalidSignature) as exc:
        raise ModelIntegrityError("manifest_signature_invalid") from exc
    actual_hash, byte_length = sha256_file(path, max_bytes=max_bytes)
    if actual_hash != manifest.artifact_sha256:
        raise ModelIntegrityError("model_artifact_hash_mismatch")
    return {"model_id":manifest.model_id,"version":manifest.version,
            "artifact_sha256":actual_hash,"byte_length":byte_length,
            "signer_key_id":manifest.signer_key_id,"signature_verified":True,
            "integrity_status":"verified"}
