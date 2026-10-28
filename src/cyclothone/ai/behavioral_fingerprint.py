"""Fixed-suite behavioral fingerprints and signed provenance attestations.

A fingerprint detects measured differences; it is not proof of model compromise,
model identity, or semantic correctness. The caller must actually run the fixed suite.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cyclothone.ai.action_verifier import canonical_json, sha256_hex

_PROTOCOL = "cyclothone.ai-model-fingerprint.v1"
_ATTESTATION_PROTOCOL = "cyclothone.ai-model-provenance.v1"
_ATTESTATION_DOMAIN = b"cyclothone.ai-model-provenance.v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _timestamp(value: datetime | None) -> str:
    stamp = value or datetime.now(UTC)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _content_hash(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return sha256_hex(raw)


@dataclass(frozen=True, slots=True)
class CaseFingerprint:
    case_id: str
    input_sha256: str
    output_sha256: str


@dataclass(frozen=True, slots=True)
class ModelBehaviorFingerprint:
    protocol: str
    suite_id: str
    suite_version: str
    model_id: str
    model_version: str
    provider_id: str
    runtime_sha256: str
    dependency_sha256: str
    cases: tuple[CaseFingerprint, ...]
    fingerprint_sha256: str
    measured_at: str

    def manifest(self) -> dict:
        return {
            "protocol": self.protocol,
            "suite_id": self.suite_id,
            "suite_version": self.suite_version,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "provider_id": self.provider_id,
            "runtime_sha256": self.runtime_sha256,
            "dependency_sha256": self.dependency_sha256,
            "cases": [
                {"case_id": c.case_id, "input_sha256": c.input_sha256, "output_sha256": c.output_sha256}
                for c in self.cases
            ],
        }


def _manifest_hash(manifest: dict) -> str:
    return sha256_hex(canonical_json(manifest).encode("utf-8"))


def build_behavioral_fingerprint(
    *,
    suite_id: str,
    suite_version: str,
    model_id: str,
    model_version: str,
    provider_id: str,
    runtime_sha256: str,
    dependency_sha256: str,
    case_inputs: Mapping[str, str | bytes],
    case_outputs: Mapping[str, str | bytes],
    measured_at: datetime | None = None,
) -> ModelBehaviorFingerprint:
    required = {
        "suite_id": suite_id,
        "suite_version": suite_version,
        "model_id": model_id,
        "model_version": model_version,
        "provider_id": provider_id,
    }
    if any(not isinstance(v, str) or not v.strip() for v in required.values()):
        raise ValueError("fingerprint_identity_fields_required")
    if not _SHA256.fullmatch(runtime_sha256) or not _SHA256.fullmatch(dependency_sha256):
        raise ValueError("runtime_and_dependency_sha256_required")
    if not case_inputs or set(case_inputs) != set(case_outputs):
        raise ValueError("fixed_suite_input_output_set_mismatch")
    if any(not isinstance(case_id, str) or not case_id.strip() for case_id in case_inputs):
        raise ValueError("case_id_required")

    cases = tuple(
        CaseFingerprint(case_id, _content_hash(case_inputs[case_id]), _content_hash(case_outputs[case_id]))
        for case_id in sorted(case_inputs)
    )
    provisional = ModelBehaviorFingerprint(
        protocol=_PROTOCOL,
        suite_id=suite_id,
        suite_version=suite_version,
        model_id=model_id,
        model_version=model_version,
        provider_id=provider_id,
        runtime_sha256=runtime_sha256,
        dependency_sha256=dependency_sha256,
        cases=cases,
        fingerprint_sha256="",
        measured_at=_timestamp(measured_at),
    )
    return replace(provisional, fingerprint_sha256=_manifest_hash(provisional.manifest()))


@dataclass(frozen=True, slots=True)
class DriftComparison:
    status: str
    reasons: tuple[str, ...]
    changed_cases: tuple[str, ...]
    baseline_sha256: str
    current_sha256: str


def compare_behavioral_fingerprints(
    baseline: ModelBehaviorFingerprint,
    current: ModelBehaviorFingerprint,
) -> DriftComparison:
    if baseline.protocol != _PROTOCOL or current.protocol != _PROTOCOL:
        return DriftComparison("incomparable", ("unsupported_fingerprint_protocol",), (),
                               baseline.fingerprint_sha256, current.fingerprint_sha256)
    if (baseline.suite_id, baseline.suite_version) != (current.suite_id, current.suite_version):
        return DriftComparison("incomparable", ("fixed_suite_version_mismatch",), (),
                               baseline.fingerprint_sha256, current.fingerprint_sha256)
    old = {case.case_id: case for case in baseline.cases}
    new = {case.case_id: case for case in current.cases}
    if set(old) != set(new):
        return DriftComparison("incomparable", ("fixed_suite_case_set_mismatch",), (),
                               baseline.fingerprint_sha256, current.fingerprint_sha256)
    reasons: list[str] = []
    if baseline.model_id != current.model_id or baseline.model_version != current.model_version:
        reasons.append("model_binding_changed")
    if baseline.provider_id != current.provider_id:
        reasons.append("provider_binding_changed")
    if baseline.runtime_sha256 != current.runtime_sha256:
        reasons.append("runtime_digest_changed")
    if baseline.dependency_sha256 != current.dependency_sha256:
        reasons.append("dependency_digest_changed")
    changed_cases = tuple(
        case_id for case_id in sorted(old)
        if old[case_id].input_sha256 != new[case_id].input_sha256
        or old[case_id].output_sha256 != new[case_id].output_sha256
    )
    if changed_cases:
        reasons.append("fixed_suite_output_or_input_changed")
    status = "stable" if not reasons and baseline.fingerprint_sha256 == current.fingerprint_sha256 else "drifted"
    if not reasons and baseline.fingerprint_sha256 != current.fingerprint_sha256:
        reasons.append("fingerprint_manifest_changed")
    return DriftComparison(status, tuple(reasons), changed_cases,
                           baseline.fingerprint_sha256, current.fingerprint_sha256)


@dataclass(frozen=True, slots=True)
class ProvenanceAttestation:
    protocol: str
    fingerprint_sha256: str
    signer_key_id: str
    created_at: str
    signature_hex: str

    def signed_body(self) -> dict[str, str]:
        return {
            "protocol": self.protocol,
            "fingerprint_sha256": self.fingerprint_sha256,
            "signer_key_id": self.signer_key_id,
            "created_at": self.created_at,
        }


def sign_provenance_attestation(
    fingerprint: ModelBehaviorFingerprint,
    *,
    signer_key_id: str,
    signing_key: Ed25519PrivateKey,
    created_at: datetime | None = None,
) -> ProvenanceAttestation:
    if _manifest_hash(fingerprint.manifest()) != fingerprint.fingerprint_sha256:
        raise ValueError("fingerprint_manifest_hash_mismatch")
    if not signer_key_id.strip():
        raise ValueError("signer_key_id_required")
    body = {
        "protocol": _ATTESTATION_PROTOCOL,
        "fingerprint_sha256": fingerprint.fingerprint_sha256,
        "signer_key_id": signer_key_id,
        "created_at": _timestamp(created_at),
    }
    signature = signing_key.sign(_ATTESTATION_DOMAIN + canonical_json(body).encode("utf-8")).hex()
    return ProvenanceAttestation(**body, signature_hex=signature)


def verify_provenance_attestation(
    fingerprint: ModelBehaviorFingerprint,
    attestation: ProvenanceAttestation,
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    if _manifest_hash(fingerprint.manifest()) != fingerprint.fingerprint_sha256:
        return False
    if attestation.protocol != _ATTESTATION_PROTOCOL:
        return False
    if attestation.fingerprint_sha256 != fingerprint.fingerprint_sha256:
        return False
    key = public_keys.get(attestation.signer_key_id)
    if key is None or not re.fullmatch(r"[0-9a-f]{128}", attestation.signature_hex):
        return False
    try:
        key.verify(
            bytes.fromhex(attestation.signature_hex),
            _ATTESTATION_DOMAIN + canonical_json(attestation.signed_body()).encode("utf-8"),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
