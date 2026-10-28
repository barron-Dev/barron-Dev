from dataclasses import replace
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.ai.behavioral_fingerprint import (
    build_behavioral_fingerprint,
    compare_behavioral_fingerprints,
    sign_provenance_attestation,
    verify_provenance_attestation,
)

RUNTIME = "a" * 64
DEPENDENCIES = "b" * 64


def _build(outputs=None, suite_version="v1", model_version="2026.10"):
    return build_behavioral_fingerprint(
        suite_id="safety-regression-suite",
        suite_version=suite_version,
        model_id="model-x",
        model_version=model_version,
        provider_id="provider-x",
        runtime_sha256=RUNTIME,
        dependency_sha256=DEPENDENCIES,
        case_inputs={"case-1": "input-a", "case-2": "input-b"},
        case_outputs=outputs or {"case-1": "allow", "case-2": "deny"},
        measured_at=datetime(2026, 10, 28, tzinfo=UTC),
    )


def test_same_fixed_suite_and_provenance_produce_stable_fingerprint():
    baseline = _build()
    current = _build()
    comparison = compare_behavioral_fingerprints(baseline, current)
    assert comparison.status == "stable"
    assert comparison.changed_cases == ()
    assert baseline.fingerprint_sha256 == current.fingerprint_sha256


def test_changed_output_is_reported_as_drift_not_compromise():
    baseline = _build()
    current = _build({"case-1": "allow", "case-2": "allow"})
    comparison = compare_behavioral_fingerprints(baseline, current)
    assert comparison.status == "drifted"
    assert comparison.changed_cases == ("case-2",)
    assert "fixed_suite_output_or_input_changed" in comparison.reasons


def test_different_suite_version_is_incomparable():
    comparison = compare_behavioral_fingerprints(_build(), _build(suite_version="v2"))
    assert comparison.status == "incomparable"
    assert comparison.reasons == ("fixed_suite_version_mismatch",)


def test_provenance_attestation_verifies_and_rejects_tampering():
    fingerprint = _build()
    private = Ed25519PrivateKey.generate()
    keys = {"model-attestation-key": private.public_key()}
    attestation = sign_provenance_attestation(
        fingerprint, signer_key_id="model-attestation-key", signing_key=private,
    )
    assert verify_provenance_attestation(fingerprint, attestation, public_keys=keys)
    assert not verify_provenance_attestation(
        fingerprint, replace(attestation, fingerprint_sha256="0" * 64), public_keys=keys,
    )
    changed_fingerprint = replace(fingerprint, model_version="different-version")
    assert not verify_provenance_attestation(changed_fingerprint, attestation, public_keys=keys)
