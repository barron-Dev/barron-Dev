from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from c2pa import Context


def _ca_pem(common_name: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_c2pa_sdk_accepts_separate_manifest_and_tsa_trust_lists():
    manifest_pem = _ca_pem("Cyclothone test manifest anchor")
    tsa_pem = _ca_pem("Cyclothone test TSA anchor")
    context = Context.from_dict({
        "trust": {
            "anchors": [
                {
                    "trust_uri": "https://example.invalid/c2pa-manifest-test",
                    "trust_kind": "manifest",
                    "trust_anchors": manifest_pem,
                    "trust_config": "1.3.6.1.4.1.62558.2.1",
                    "allowed_list": None,
                    "trusted_ica_issuers": None,
                },
                {
                    "trust_uri": "https://example.invalid/c2pa-tsa-test",
                    "trust_kind": "tsa",
                    "trust_anchors": tsa_pem,
                    "trust_config": "1.3.6.1.5.5.7.3.8",
                    "allowed_list": None,
                    "trusted_ica_issuers": None,
                },
            ]
        },
        "verify": {
            "verify_after_reading": True,
            "verify_trust": True,
            "verify_timestamp_trust": True,
            "remote_manifest_fetch": False,
            "ocsp_fetch": False,
            "strict_v1_validation": True,
        },
    })
    assert context.is_valid
    context.close()
