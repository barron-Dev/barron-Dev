"""Signed, offline-verifiable Cyclothone pack release envelopes.

The deterministic compiled artifact remains the payload. Signatures are detached
from its digest so key metadata never contaminates deterministic compilation.
This does not claim HSM, SLSA, revocation distribution, or runtime sandboxing.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class PackReleaseError(ValueError):
    """A compiled pack is invalid or its release signature cannot be trusted."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackReleaseError(f"release_json_read_failed:{type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise PackReleaseError("release_document_must_be_object")
    return value


def verify_compiled_digest(artifact: dict[str, Any]) -> str:
    supplied = artifact.get("artifact_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64 or any(c not in "0123456789abcdef" for c in supplied):
        raise PackReleaseError("compiled_artifact_digest_missing_or_invalid")
    payload = dict(artifact)
    payload.pop("artifact_sha256", None)
    actual = hashlib.sha256(_canonical(payload)).hexdigest()
    if actual != supplied:
        raise PackReleaseError("compiled_artifact_digest_mismatch")
    if artifact.get("artifact_type") != "cyclothone.reference_pack":
        raise PackReleaseError("unsupported_compiled_artifact_type")
    if artifact.get("publication_state") not in {"compiled_unconformed", "conformant"}:
        raise PackReleaseError("preview_or_unresolved_pack_cannot_be_signed")
    if artifact.get("publication_state") == "conformant":
        conformance = artifact.get("conformance")
        if not isinstance(conformance, dict) or conformance.get("status") != "passed" or not conformance.get("artifact_digest"):
            raise PackReleaseError("conformance_attestation_missing")
    return supplied


def sign_compiled_pack(
    artifact_path: str | Path,
    private_key_path: str | Path,
    key_id: str,
    output_path: str | Path,
) -> dict[str, Any]:
    if not key_id or len(key_id) > 200:
        raise PackReleaseError("invalid_signing_key_id")
    artifact = _load_json(artifact_path)
    digest = verify_compiled_digest(artifact)
    try:
        loaded = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise PackReleaseError(f"private_key_load_failed:{type(exc).__name__}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise PackReleaseError("signing_key_must_be_ed25519")
    manifest = {
        "format": "cyclothone.pack.bundle",
        "format_version": 1,
        "pack_id": artifact.get("pack_id"),
        "artifact_sha256": digest,
        "signing_algorithm": "Ed25519",
        "key_id": key_id,
    }
    signature = loaded.sign(_canonical(manifest))
    envelope = {
        "manifest": manifest,
        "artifact": artifact,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    Path(output_path).write_bytes(_canonical(envelope) + b"\n")
    return envelope


def verify_signed_pack(
    bundle_path: str | Path,
    public_key_path: str | Path,
) -> dict[str, Any]:
    envelope = _load_json(bundle_path)
    manifest = envelope.get("manifest")
    artifact = envelope.get("artifact")
    signature_text = envelope.get("signature")
    if not isinstance(manifest, dict) or not isinstance(artifact, dict) or not isinstance(signature_text, str):
        raise PackReleaseError("signed_bundle_shape_invalid")
    if manifest.get("format") != "cyclothone.pack.bundle" or manifest.get("format_version") != 1:
        raise PackReleaseError("unsupported_bundle_format")
    if manifest.get("signing_algorithm") != "Ed25519":
        raise PackReleaseError("unsupported_signing_algorithm")
    digest = verify_compiled_digest(artifact)
    if manifest.get("artifact_sha256") != digest or manifest.get("pack_id") != artifact.get("pack_id"):
        raise PackReleaseError("manifest_artifact_binding_mismatch")
    try:
        loaded = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        signature = base64.b64decode(signature_text, validate=True)
    except (OSError, ValueError, TypeError) as exc:
        raise PackReleaseError(f"verification_material_invalid:{type(exc).__name__}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise PackReleaseError("verification_key_must_be_ed25519")
    try:
        loaded.verify(signature, _canonical(manifest))
    except InvalidSignature as exc:
        raise PackReleaseError("pack_signature_invalid") from exc
    return {
        "verified": True,
        "pack_id": artifact["pack_id"],
        "artifact_sha256": digest,
        "key_id": manifest["key_id"],
        "publication_state": artifact["publication_state"],
    }
