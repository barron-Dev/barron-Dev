from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

STATES = {"VALID", "INVALID", "UNTRUSTED", "MISSING_PROVENANCE", "INDETERMINATE"}
ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class ProvenanceResult:
    validation_state: str
    media_sha256: str
    manifest_store_sha256: str | None
    signer_identity: str | None
    report: dict[str, Any]
    sdk_version: str


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _walk_strings(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower(), child
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def classify_validation(state: str | None, results: Any, has_trust_anchors: bool) -> str:
    if not state:
        return "INDETERMINATE"
    normalized = state.strip().lower()
    if normalized in {"valid", "trusted", "success"}:
        return "VALID" if has_trust_anchors else "UNTRUSTED"
    if normalized in {"invalid", "error", "failure"}:
        codes = []
        for key, value in _walk_strings(results or {}):
            if key in {"code", "validation_status", "status", "name"} and isinstance(value, str):
                codes.append(value.lower())
        trust_markers = ("untrusted", "trust anchor", "certificate chain", "certificatetrust", "unknown root", "not trusted")
        integrity_markers = ("hash.mismatch", "hash mismatch", "hard binding", "signature.invalid", "invalid signature", "claim.signature")
        if any(any(marker in code for marker in trust_markers) for code in codes):
            return "UNTRUSTED"
        if any(any(marker in code for marker in integrity_markers) for code in codes):
            return "INVALID"
        return "INDETERMINATE"
    return "INDETERMINATE"


def verify_c2pa_file(file_path: str | Path, trust_anchors_pem: str) -> ProvenanceResult:
    path = Path(file_path)
    digest = hashlib.sha256()
    with path.open("rb") as media:
        for chunk in iter(lambda: media.read(1024 * 1024), b""):
            digest.update(chunk)
    media_sha256 = digest.hexdigest()
    if not trust_anchors_pem.strip():
        return ProvenanceResult("INDETERMINATE", media_sha256, None, None,
                                {"error": "No versioned C2PA trust anchors configured."}, "unavailable")
    try:
        import c2pa
        from c2pa import Context, Reader
        sdk_version = getattr(c2pa, "__version__", "unknown")
        context = Context.from_dict({
            "trust": {"trust_anchors": trust_anchors_pem},
            "verify": {
                "verify_after_reading": True, "verify_trust": True,
                "verify_timestamp_trust": True, "remote_manifest_fetch": False,
                "ocsp_fetch": False, "strict_v1_validation": True,
            },
        })
        with context:
            with Reader(str(path), context=context) as reader:
                manifest_store = json.loads(reader.json())
                manifest_hash = hashlib.sha256(canonical_json(manifest_store)).hexdigest()
                active_id = manifest_store.get("active_manifest")
                manifests = manifest_store.get("manifests") or {}
                active = manifests.get(active_id) if active_id else None
                if not isinstance(active, dict):
                    return ProvenanceResult("INDETERMINATE", media_sha256, manifest_hash, None,
                                            {"error": "Active manifest missing."}, sdk_version)
                validation_state = reader.get_validation_state()
                validation_results = reader.get_validation_results()
                mapped = classify_validation(validation_state, validation_results, True)
                signature_info = active.get("signature_info") or {}
                signer = signature_info.get("issuer") or signature_info.get("common_name")
                report = {
                    "validation_state": validation_state, "validation_results": validation_results,
                    "active_manifest": active_id, "manifest": active,
                    "reader_embedded": reader.is_embedded(), "remote_manifest_used": False,
                    "policy_mode": "strict_v1_validation",
                }
                return ProvenanceResult(mapped, media_sha256, manifest_hash, signer, report, sdk_version)
    except Exception as exc:
        message = str(exc)
        missing_markers = ("manifest not found", "no manifest", "manifestnotfound", "no c2pa")
        mapped = "MISSING_PROVENANCE" if any(marker in message.lower() for marker in missing_markers) else "INDETERMINATE"
        return ProvenanceResult(mapped, media_sha256, None, None,
                                {"error_type": type(exc).__name__, "error": message[:1000]}, "unknown")


def sign_receipt(payload: dict[str, Any]) -> tuple[str, str]:
    pem = os.environ.get("CYCLOTHONE_PROVENANCE_ED25519_PRIVATE_KEY", "")
    key_id = os.environ.get("CYCLOTHONE_PROVENANCE_SIGNING_KEY_ID", "")
    if not pem or not key_id:
        raise RuntimeError("Provenance receipt signing key is not configured.")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Configured provenance signing key must be Ed25519.")
    return key.sign(canonical_json(payload)).hex(), key_id


def build_receipt_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()
