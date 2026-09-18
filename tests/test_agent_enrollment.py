from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cyclothone.api.routes.agent_enrollment import EnrollmentRequest, enroll_agent


def _ca_and_key() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cyclothone Device Test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _csr_pem() -> tuple[str, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cyclothone-e2e-test")]))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


@pytest.mark.asyncio
async def test_enrollment_issues_client_certificate_and_persists_no_private_key():
    ca_cert, ca_key = _ca_and_key()
    csr_pem, device_key = _csr_pem()
    token = "test-enrollment-token-" + "x" * 16
    rpc = AsyncMock(
        return_value=[{
            "device_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "token_id": str(uuid4()),
        }]
    )

    with (
        patch.dict(
            "os.environ",
            {
                "CYCLOTHONE_DEVICE_CA_CERT_PEM": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                "CYCLOTHONE_DEVICE_CA_KEY_PEM": ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
                "CYCLOTHONE_DEVICE_CERT_TTL_SECONDS": "3600",
            },
            clear=False,
        ),
        patch("cyclothone.api.routes.agent_enrollment.supabase.rpc", new=rpc),
    ):
        result = await enroll_agent(
            EnrollmentRequest(
                token=token,
                name="e2e-test-device",
                hostname="e2e-test-host",
                os="windows",
                os_version="11",
                arch="x86_64",
                platform="windows",
                platform_version="11",
                agent_version="test",
                csr_pem=csr_pem,
            )
        )

    cert = x509.load_pem_x509_certificate(result["certificate_pem"].encode())
    assert cert.issuer == ca_cert.subject
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "cyclothone-e2e-test"
    assert cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == device_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value

    payload = rpc.await_args.args[1]
    assert "private_key" not in payload
    assert "p_private_key" not in payload
    assert payload["p_token_hash"] != token
    assert len(payload["p_token_hash"]) == 64
    assert result["device_id"]
    assert result["tenant_id"]
