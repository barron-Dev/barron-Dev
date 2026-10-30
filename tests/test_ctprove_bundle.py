from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.verify_ctprove_bundle import canonical_json, verify_bundle


def _make_bundle(path: Path, private_key: Ed25519PrivateKey) -> tuple[dict, Path]:
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    media = Path(path.parent / "original.bin")
    media.write_bytes(b"cyclothone test media")
    import hashlib
    media_hash = hashlib.sha256(media.read_bytes()).hexdigest()
    payload = {
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "media_sha256": media_hash,
        "manifest_store_sha256": None,
        "validation_state": "MISSING_PROVENANCE",
        "signer_identity": None,
        "trust_policy_id": "00000000-0000-0000-0000-000000000002",
        "trust_policy_version": "test-v1",
        "sdk_version": "0.38.0",
        "previous_receipt_hash": "0" * 64,
        "created_at": "2026-10-30T10:00:00+00:00",
        "ml_assessment": {"status": "not_requested", "influences_cryptographic_state": False},
    }
    canonical = canonical_json(payload)
    import hashlib
    receipt_hash = hashlib.sha256(canonical).hexdigest()
    receipt = {
        "receipt_id": "00000000-0000-0000-0000-000000000003",
        "tenant_id": payload["tenant_id"],
        "media_sha256": media_hash,
        "manifest_store_sha256": None,
        "validation_state": payload["validation_state"],
        "trust_policy_version": payload["trust_policy_version"],
        "previous_receipt_hash": payload["previous_receipt_hash"],
        "receipt_hash": receipt_hash,
        "signed_payload": payload,
        "signed_payload_canonical": canonical.decode("utf-8"),
        "signature": private_key.sign(canonical).hex(),
        "signing_key_id": "test-key",
        "signing_public_key": base64.b64encode(public_raw).decode("ascii"),
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("receipt.json", json.dumps(receipt))
        archive.writestr("c2pa-report.json", json.dumps({"reason": "no manifest"}))
    trusted_path = path.parent / "trusted.pem"
    trusted_path.write_bytes(public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return receipt, trusted_path


def test_bundle_signature_and_media_hash_verify(tmp_path: Path):
    bundle = tmp_path / "evidence.ctprove"
    _, trusted = _make_bundle(bundle, Ed25519PrivateKey.generate())
    result = verify_bundle(bundle, trusted, tmp_path / "original.bin")
    assert result["signature_valid"] is True
    assert result["trusted_signer_key"] is True
    assert result["original_media_hash_matches"] is True


def test_bundle_refuses_untrusted_embedded_key(tmp_path: Path):
    bundle = tmp_path / "evidence.ctprove"
    _, trusted = _make_bundle(bundle, Ed25519PrivateKey.generate())
    wrong = Ed25519PrivateKey.generate().public_key()
    wrong_path = tmp_path / "wrong.pem"
    wrong_path.write_bytes(wrong.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    with pytest.raises(ValueError, match="independently trusted"):
        verify_bundle(bundle, wrong_path)


def test_bundle_detects_tampered_payload(tmp_path: Path):
    bundle = tmp_path / "evidence.ctprove"
    receipt, trusted = _make_bundle(bundle, Ed25519PrivateKey.generate())
    receipt["signed_payload"]["validation_state"] = "VALID"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("receipt.json", json.dumps(receipt))
        archive.writestr("c2pa-report.json", json.dumps({"reason": "no manifest"}))
    with pytest.raises(ValueError):
        verify_bundle(bundle, trusted)
