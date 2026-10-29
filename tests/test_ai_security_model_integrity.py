import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyclothone.ai_security.model_integrity import (
    ModelIntegrityError, ModelManifest, verify_model_artifact,
)


def _manifest(path, key):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    unsigned = ModelManifest("detector", "1.2.0", digest, "registry-key", "", "onnx", "1")
    sig = key.sign(unsigned.signed_payload()).hex()
    return ModelManifest("detector", "1.2.0", digest, "registry-key", sig, "onnx", "1")


def test_signed_manifest_and_artifact_verify(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(b"real test artifact bytes")
    key = Ed25519PrivateKey.generate()
    result = verify_model_artifact(path, _manifest(path, key),
                                   trusted_signers={"registry-key": key.public_key()})
    assert result["integrity_status"] == "verified"
    assert result["artifact_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_modified_artifact_is_rejected(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(b"first")
    key = Ed25519PrivateKey.generate()
    manifest = _manifest(path, key)
    path.write_bytes(b"modified")
    with pytest.raises(ModelIntegrityError, match="model_artifact_hash_mismatch"):
        verify_model_artifact(path, manifest, trusted_signers={"registry-key": key.public_key()})


def test_untrusted_signer_is_rejected(tmp_path):
    path = tmp_path / "model.bin"
    path.write_bytes(b"artifact")
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ModelIntegrityError, match="manifest_signer_not_trusted"):
        verify_model_artifact(path, _manifest(path, key), trusted_signers={})
