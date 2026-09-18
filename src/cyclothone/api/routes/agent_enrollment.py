from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/agent/enroll", tags=["agent-enrollment"])


class EnrollmentRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    name: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(min_length=1, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    arch: str | None = Field(default=None, max_length=128)
    platform: str = Field(min_length=1, max_length=128)
    platform_version: str | None = Field(default=None, max_length=128)
    agent_version: str | None = Field(default=None, max_length=128)
    csr_pem: str = Field(min_length=100, max_length=20000)


def _env_pem(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not configured")
    return value.replace("\\n", "\n").encode("utf-8")


def _load_ca() -> tuple[x509.Certificate, Any]:
    try:
        cert = x509.load_pem_x509_certificate(_env_pem("CYCLOTHONE_DEVICE_CA_CERT_PEM"))
        key = serialization.load_pem_private_key(
            _env_pem("CYCLOTHONE_DEVICE_CA_KEY_PEM"), password=None
        )
    except Exception as exc:
        raise RuntimeError("device CA configuration is invalid") from exc

    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca:
            raise RuntimeError("configured device CA certificate is not a CA")
    except x509.ExtensionNotFound as exc:
        raise RuntimeError("device CA certificate lacks CA basic constraints") from exc

    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        raise RuntimeError("unsupported device CA private key type")
    return cert, key


def _sign(builder: x509.CertificateBuilder, key: Any) -> x509.Certificate:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return builder.sign(private_key=key, algorithm=None)
    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def _issue_certificate(csr: x509.CertificateSigningRequest) -> tuple[x509.Certificate, x509.Certificate]:
    ca_cert, ca_key = _load_ca()
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    subject = csr.subject
    if not subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        raise ValueError("CSR common name is required")

    now = datetime.now(timezone.utc)
    requested_ttl = int(os.environ.get("CYCLOTHONE_DEVICE_CERT_TTL_SECONDS", "2592000"))
    ttl = min(max(requested_ttl, 3600), 31536000)
    not_before = now - timedelta(seconds=30)
    not_after = now + timedelta(seconds=ttl)
    ca_not_after = ca_cert.not_valid_after_utc
    if not_after > ca_not_after:
        not_after = ca_not_after - timedelta(seconds=30)
    if not_after <= now:
        raise ValueError("device CA certificate expires before the requested device certificate")

    serial = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    return _sign(builder, ca_key), ca_cert


def _public_key_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


@router.post("", status_code=status.HTTP_201_CREATED)
async def enroll_agent(body: EnrollmentRequest) -> dict[str, Any]:
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()

    try:
        csr = x509.load_pem_x509_csr(body.csr_pem.encode("utf-8"))
        certificate, ca_cert = _issue_certificate(csr)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid enrollment CSR") from exc

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    serial = format(certificate.serial_number, "x")

    try:
        result = await supabase.rpc(
            "enroll_device_atomic",
            {
                "p_token_hash": token_hash,
                "p_name": body.name,
                "p_hostname": body.hostname,
                "p_os": body.os,
                "p_os_version": body.os_version,
                "p_arch": body.arch,
                "p_platform": body.platform,
                "p_platform_version": body.platform_version,
                "p_agent_version": body.agent_version,
                "p_public_key_pem": _public_key_pem(csr),
                "p_certificate_pem": cert_pem,
                "p_certificate_serial": serial,
                "p_certificate_not_before": certificate.not_valid_before_utc.isoformat(),
                "p_certificate_not_after": certificate.not_valid_after_utc.isoformat(),
                "p_cert_fingerprint": fingerprint,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="enrollment token is invalid, expired, already used, or device identity conflicts") from exc

    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict) or not row.get("device_id") or not row.get("tenant_id"):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="device enrollment did not produce an identity")

    # The agent generates and retains the private key; the server receives only the CSR
    # and the corresponding public certificate identity. No private key is persisted.
    return {
        "device_id": str(row["device_id"]),
        "tenant_id": str(row["tenant_id"]),
        "certificate_pem": cert_pem,
        "ca_certificate_pem": ca_pem,
        "certificate_serial": serial,
        "certificate_not_before": certificate.not_valid_before_utc.isoformat(),
        "certificate_not_after": certificate.not_valid_after_utc.isoformat(),
        "cert_fingerprint": fingerprint,
    }
