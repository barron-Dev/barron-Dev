from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.compliance.trust_crypto import (
    verify_ed25519_pem_signature,
    verify_ed25519_raw_signature,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_raw_ed25519_verification_accepts_valid_signature():
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    digest = _digest("cyclothone-trust-measurement")
    signature_hex = private.sign(digest.encode("ascii")).hex()

    assert verify_ed25519_raw_signature(public_hex, signature_hex, digest) is True


def test_raw_ed25519_verification_rejects_tampered_payload():
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    digest = _digest("original")
    signature_hex = private.sign(digest.encode("ascii")).hex()
    tampered_digest = _digest("tampered")

    assert verify_ed25519_raw_signature(public_hex, signature_hex, tampered_digest) is False


def test_raw_ed25519_verification_rejects_wrong_key():
    signer = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    public_hex = other.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    digest = _digest("bound-to-signer")
    signature_hex = signer.sign(digest.encode("ascii")).hex()

    assert verify_ed25519_raw_signature(public_hex, signature_hex, digest) is False


@pytest.mark.parametrize(
    "public_key_hex,signature_hex,digest",
    [
        ("00" * 31, "00" * 64, "a" * 64),
        ("00" * 32, "00" * 63, "a" * 64),
        ("00" * 32, "00" * 64, "not-a-sha256"),
        ("zz" * 32, "00" * 64, "a" * 64),
    ],
)
def test_raw_ed25519_verification_rejects_invalid_encoding(
    public_key_hex: str, signature_hex: str, digest: str
):
    assert verify_ed25519_raw_signature(public_key_hex, signature_hex, digest) is False


def test_pem_ed25519_verification_accepts_valid_signature():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    digest = _digest("certificate-payload")
    signature_b64 = base64.b64encode(private.sign(digest.encode("ascii"))).decode("ascii")

    assert verify_ed25519_pem_signature(public_pem, signature_b64, digest) is True


def test_pem_ed25519_verification_rejects_tampered_signature():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    digest = _digest("certificate-payload")
    signature = bytearray(private.sign(digest.encode("ascii")))
    signature[0] ^= 0x01
    signature_b64 = base64.b64encode(bytes(signature)).decode("ascii")

    assert verify_ed25519_pem_signature(public_pem, signature_b64, digest) is False


def test_pem_verification_rejects_non_ed25519_key():
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = rsa.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    assert verify_ed25519_pem_signature(public_pem, base64.b64encode(b"x" * 64).decode(), "a" * 64) is False
