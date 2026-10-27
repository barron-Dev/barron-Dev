from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.packs.compiler import build_pack
from cyclothone.packs.release import PackReleaseError, sign_compiled_pack, verify_signed_pack


def _keypair(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


def _conformant_artifact():
    artifact = build_pack({
        "schema_version": 1, "pack_id": "bank-core", "industry": "financial",
        "sub_segment": "banking", "geography": "sa",
        "asset_types": {"identity": {"scope": "critical"}},
        "services_in_scope": {"required": ["identity"], "optional": []},
        "compliance_packs": ["baseline"], "delivery_bindings": {
            "default": "console", "allowed": ["console"], "forbidden": ["public_webhook"],
        },
        "data_residency": {"default_region": "sa-central", "cross_border_forbidden": True},
        "retention": {"min_days": 90, "worm": True},
        "approval": {"dual_control": True, "roles": ["security_owner", "risk_owner"]},
        "workflows": ["evaluate"], "failure_tests": ["tenant_boundary"],
        "ttfvr_target_seconds": 300,
    }, known_services={"identity"}, known_delivery_bindings={"console", "public_webhook"})
    artifact["publication_state"] = "conformant"
    artifact["conformance"] = {"status": "passed", "artifact_digest": "c" * 64}
    import hashlib
    canonical = json.dumps(
        {key: value for key, value in artifact.items() if key != "artifact_sha256"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()
    artifact["artifact_sha256"] = hashlib.sha256(canonical).hexdigest()
    return artifact


def test_conformant_pack_signs_and_verifies_offline(tmp_path):
    private, public = _keypair(tmp_path)
    artifact = _conformant_artifact()
    artifact_path = tmp_path / "compiled.json"
    bundle_path = tmp_path / "pack.bundle"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    sign_compiled_pack(artifact_path, private, "release-key-2026-01", bundle_path)
    verified = verify_signed_pack(bundle_path, public)

    assert verified["verified"] is True
    assert verified["pack_id"] == "bank-core"
    assert verified["key_id"] == "release-key-2026-01"
    assert verified["artifact_sha256"] == artifact["artifact_sha256"]


def test_preview_artifact_cannot_be_signed(tmp_path):
    private, _ = _keypair(tmp_path)
    artifact = _conformant_artifact()
    artifact["publication_state"] = "preview"
    import hashlib
    artifact.pop("artifact_sha256")
    artifact["artifact_sha256"] = hashlib.sha256(json.dumps(
        {key: value for key, value in artifact.items() if key != "artifact_sha256"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    artifact_path = tmp_path / "preview.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    with pytest.raises(PackReleaseError, match="only_conformant"):
        sign_compiled_pack(artifact_path, private, "test-key", tmp_path / "pack.bundle")


def test_tampered_artifact_is_rejected_before_signing(tmp_path):
    private, _ = _keypair(tmp_path)
    artifact = _conformant_artifact()
    artifact["source_pack"]["geography"] = "us"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    with pytest.raises(PackReleaseError, match="digest_mismatch"):
        sign_compiled_pack(path, private, "test-key", tmp_path / "pack.bundle")


def test_bundle_tampering_invalidates_signature(tmp_path):
    private, public = _keypair(tmp_path)
    artifact = _conformant_artifact()
    source = tmp_path / "compiled.json"
    bundle = tmp_path / "pack.bundle"
    source.write_text(json.dumps(artifact), encoding="utf-8")
    sign_compiled_pack(source, private, "test-key", bundle)
    envelope = json.loads(bundle.read_text(encoding="utf-8"))
    envelope["manifest"]["key_id"] = "attacker-key"
    bundle.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(PackReleaseError, match="signature_invalid"):
        verify_signed_pack(bundle, public)


def test_bundle_cannot_swap_artifact_without_matching_manifest(tmp_path):
    private, public = _keypair(tmp_path)
    artifact = _conformant_artifact()
    source = tmp_path / "compiled.json"
    bundle = tmp_path / "pack.bundle"
    source.write_text(json.dumps(artifact), encoding="utf-8")
    sign_compiled_pack(source, private, "test-key", bundle)
    envelope = json.loads(bundle.read_text(encoding="utf-8"))
    envelope["artifact"]["pack_id"] = "other-pack"
    bundle.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(PackReleaseError, match="digest_mismatch"):
        verify_signed_pack(bundle, public)
