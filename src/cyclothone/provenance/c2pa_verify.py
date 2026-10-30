from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID

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
    if normalized == "trusted":
        tsa_failures = ("timestamp.untrusted", "timestamp.mismatch", "timestamp.malformed",
                        "timestamp.outsidevalidity", "timestamp.credentialinvalid")
        result_strings = [str(value).lower() for _, value in _walk_strings(results or {})]
        if any(marker in value for marker in tsa_failures for value in result_strings):
            return "UNTRUSTED"
        return "VALID" if has_trust_anchors else "UNTRUSTED"
    if normalized == "valid":
        return "UNTRUSTED"
    if normalized in {"invalid", "error", "failure"}:
        codes = [
            str(value).lower()
            for key, value in _walk_strings(results or {})
            if key == "code" and isinstance(value, str)
        ]
        trust_markers = (
            "signingcredential.untrusted", "signingcredential.expired",
            "signingcredential.revoked", "signingcredential.invalid", "ocsp.revoked",
            "timestamp.untrusted", "timestamp.mismatch", "timestamp.malformed",
            "timestamp.outsidevalidity", "timestamp.credentialinvalid",
        )
        if any(marker in code for marker in trust_markers for code in codes):
            return "UNTRUSTED"
        integrity_markers = (
            "claimsignature.mismatch", "assertion.hasheduri.mismatch",
            "assertion.datahash.mismatch", "assertion.bmffhash.mismatch",
            "assertion.boxeshash.mismatch", "assertion.collectionhash.mismatch",
        )
        if any(marker in code for marker in integrity_markers for code in codes):
            return "INVALID"
        return "INDETERMINATE"
    return "INDETERMINATE"


def validate_trust_policy(anchor_pems: list[str], expected_sha256: list[str]) -> str:
    if not anchor_pems or not expected_sha256 or len(anchor_pems) != len(expected_sha256):
        raise ValueError("Trust policy must contain matching CA anchor certificates and SHA-256 fingerprints.")
    actual = []
    for pem in anchor_pems:
        certificates = x509.load_pem_x509_certificates(pem.encode("utf-8"))
        if not certificates:
            raise ValueError("Trust policy contains an empty certificate bundle.")
        for cert in certificates:
            constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not constraints.ca:
                raise ValueError("Trust policy contains a certificate that is not a CA trust anchor.")
            try:
                usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not usage.key_cert_sign:
                    raise ValueError("Trust anchor certificate lacks keyCertSign usage.")
            except x509.ExtensionNotFound:
                pass
            actual.append(cert.fingerprint(hashes.SHA256()).hex())
    if sorted(actual) != sorted(item.lower() for item in expected_sha256):
        raise ValueError("Trust policy certificate fingerprints do not match the configured trust anchors.")
    return "\n".join(anchor_pems)


def verify_c2pa_file(
    file_path: str | Path, manifest_trust_anchors_pem: str, tsa_trust_anchors_pem: str,
    manifest_trust_uri: str | None = None, tsa_trust_uri: str | None = None,
) -> ProvenanceResult:
    path = Path(file_path)
    digest = hashlib.sha256()
    with path.open("rb") as media:
        for chunk in iter(lambda: media.read(1024 * 1024), b""):
            digest.update(chunk)
    media_sha256 = digest.hexdigest()
    if not manifest_trust_anchors_pem.strip() or not tsa_trust_anchors_pem.strip():
        return ProvenanceResult("INDETERMINATE", media_sha256, None, None,
                                {"error": "Separate manifest and TSA trust anchors are required."}, "unavailable")
    try:
        import c2pa
        from c2pa import Context, Reader
        sdk_version = getattr(c2pa, "__version__", "unknown")
        context = Context.from_dict({
            "trust": {
                "anchors": [
                    {
                        "trust_uri": manifest_trust_uri,
                        "trust_kind": "manifest",
                        "trust_anchors": manifest_trust_anchors_pem,
                        "trust_config": "1.3.6.1.4.1.62558.2.1",
                        "allowed_list": None,
                        "trusted_ica_issuers": None,
                    },
                    {
                        "trust_uri": tsa_trust_uri,
                        "trust_kind": "tsa",
                        "trust_anchors": tsa_trust_anchors_pem,
                        "trust_config": "1.3.6.1.5.5.7.3.8",
                        "allowed_list": None,
                        "trusted_ica_issuers": None,
                    },
                ]
            },
            "verify": {
                "verify_after_reading": True, "verify_trust": True,
                "verify_timestamp_trust": True,
                "remote_manifest_fetch": False, "ocsp_fetch": False,
                "strict_v1_validation": True,
            },
        })
        with context:
            reader = Reader.try_create(str(path), context=context)
            if reader is None:
                return ProvenanceResult(
                    "MISSING_PROVENANCE", media_sha256, None, None,
                    {"reason": "The official C2PA Reader found no embedded manifest."}, sdk_version,
                )
            with reader:
                manifest_store = json.loads(reader.json())
                manifest_hash = hashlib.sha256(canonical_json(manifest_store)).hexdigest()
                active = reader.get_active_manifest()
                if not isinstance(active, dict):
                    return ProvenanceResult("INDETERMINATE", media_sha256, manifest_hash, None,
                                            {"error": "Active manifest missing."}, sdk_version)
                validation_state = reader.get_validation_state()
                validation_results = reader.get_validation_results()
                mapped = classify_validation(validation_state, validation_results, True)
                signature_info = active.get("signature_info") or {}
                signer = signature_info.get("common_name") or signature_info.get("issuer")
                report = {
                    "validation_state": validation_state, "validation_results": validation_results,
                    "active_manifest": manifest_store.get("active_manifest"),
                    "manifest": active, "manifest_store": manifest_store,
                    "reader_embedded": reader.is_embedded(), "remote_manifest_used": False,
                    "policy_mode": "strict_v1_validation",
                    "revocation_check": "not_performed",
                    "signer_identity_interpretation": "certificate subject/issuer claim; not proof of depicted identity",
                }
                return ProvenanceResult(mapped, media_sha256, manifest_hash, signer, report, sdk_version)
    except Exception as exc:
        message = str(exc)
        return ProvenanceResult("INDETERMINATE", media_sha256, None, None,
                                {"error_type": type(exc).__name__, "error": message[:1000]}, "unknown")


def sign_receipt(payload: dict[str, Any]) -> tuple[str, str, str]:
    pem = os.environ.get("CYCLOTHONE_PROVENANCE_ED25519_PRIVATE_KEY", "")
    key_id = os.environ.get("CYCLOTHONE_PROVENANCE_SIGNING_KEY_ID", "")
    if not pem or not key_id:
        raise RuntimeError("Provenance receipt signing key is not configured.")
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Configured provenance signing key must be Ed25519.")
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key.sign(canonical_json(payload)).hex(), key_id, base64.b64encode(public_key).decode("ascii")


def build_receipt_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()
