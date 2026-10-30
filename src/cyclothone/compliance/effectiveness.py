from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from cyclothone.compliance.signing import sign_digest, verify_digest_signature

ReceiptStatus = Literal["effective", "ineffective", "partial", "unknown"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_STATUSES = {"effective", "ineffective", "partial", "unknown"}


class EffectivenessReceiptError(ValueError):
    """Raised when a receipt cannot be safely normalized or verified."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EffectivenessReceiptError("receipt payload must be finite JSON data") from exc


def _digest(value: str, field: str) -> str:
    normalized = str(value).lower()
    if not _SHA256.fullmatch(normalized):
        raise EffectivenessReceiptError(f"{field} must be a lowercase SHA-256 digest")
    return normalized


@dataclass(frozen=True, slots=True)
class EffectivenessReceipt:
    """Immutable, tenant-bound record of one versioned effectiveness probe.

    A receipt is evidence of the stated observation only. It is not a
    certification, an auditor opinion, or proof beyond its declared scope.
    """

    tenant_id: str
    assessment_id: str
    control_id: str
    probe_id: str
    probe_version: str
    scope_digest: str
    input_digest: str
    observations: dict[str, Any]
    expected_outcome: str
    observed_outcome: str
    status: ReceiptStatus
    coverage: float
    evidence_digest: str
    signer_key_id: str
    signature_b64: str
    receipt_digest: str
    issued_at: datetime

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": "cyclothone.effectiveness-receipt.v1",
            "tenant_id": str(UUID(self.tenant_id)),
            "assessment_id": str(UUID(self.assessment_id)),
            "control_id": self.control_id,
            "probe_id": self.probe_id,
            "probe_version": self.probe_version,
            "scope_digest": _digest(self.scope_digest, "scope_digest"),
            "input_digest": _digest(self.input_digest, "input_digest"),
            "observations": self.observations,
            "expected_outcome": self.expected_outcome,
            "observed_outcome": self.observed_outcome,
            "status": self.status,
            "coverage": self.coverage,
            "evidence_digest": _digest(self.evidence_digest, "evidence_digest"),
            "issued_at": self.issued_at.astimezone(UTC).isoformat(),
        }


def receipt_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def validate_receipt_fields(
    *,
    tenant_id: str,
    assessment_id: str,
    control_id: str,
    probe_id: str,
    probe_version: str,
    scope_digest: str,
    input_digest: str,
    observations: dict[str, Any],
    expected_outcome: str,
    observed_outcome: str,
    status: str,
    coverage: float,
    evidence_digest: str,
) -> None:
    try:
        UUID(str(tenant_id))
        UUID(str(assessment_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise EffectivenessReceiptError("tenant_id and assessment_id must be UUIDs") from exc
    for name, value in (
        ("control_id", control_id),
        ("probe_id", probe_id),
        ("probe_version", probe_version),
        ("expected_outcome", expected_outcome),
        ("observed_outcome", observed_outcome),
    ):
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise EffectivenessReceiptError(f"{name} must be a non-empty bounded string")
    if not isinstance(status, str) or status not in _ALLOWED_STATUSES:
        raise EffectivenessReceiptError("unsupported receipt status")
    if isinstance(coverage, bool) or not isinstance(coverage, (int, float)) or not 0 <= coverage <= 1:
        raise EffectivenessReceiptError("coverage must be a number between 0 and 1")
    if not isinstance(observations, dict):
        raise EffectivenessReceiptError("observations must be a JSON object")
    _digest(scope_digest, "scope_digest")
    _digest(input_digest, "input_digest")
    _digest(evidence_digest, "evidence_digest")
    _canonical_json(observations)


async def create_effectiveness_receipt(
    *,
    tenant_id: UUID,
    assessment_id: UUID,
    control_id: str,
    probe_id: str,
    probe_version: str,
    scope_digest: str,
    input_digest: str,
    observations: dict[str, Any],
    expected_outcome: str,
    observed_outcome: str,
    status: ReceiptStatus,
    coverage: float,
    evidence_digest: str,
    issued_at: datetime | None = None,
) -> EffectivenessReceipt:
    validate_receipt_fields(
        tenant_id=str(tenant_id),
        assessment_id=str(assessment_id),
        control_id=control_id,
        probe_id=probe_id,
        probe_version=probe_version,
        scope_digest=scope_digest,
        input_digest=input_digest,
        observations=observations,
        expected_outcome=expected_outcome,
        observed_outcome=observed_outcome,
        status=status,
        coverage=coverage,
        evidence_digest=evidence_digest,
    )
    timestamp = issued_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise EffectivenessReceiptError("issued_at must be timezone-aware")
    timestamp = timestamp.astimezone(UTC)
    payload = {
        "schema": "cyclothone.effectiveness-receipt.v1",
        "tenant_id": str(tenant_id),
        "assessment_id": str(assessment_id),
        "control_id": control_id,
        "probe_id": probe_id,
        "probe_version": probe_version,
        "scope_digest": _digest(scope_digest, "scope_digest"),
        "input_digest": _digest(input_digest, "input_digest"),
        "observations": observations,
        "expected_outcome": expected_outcome,
        "observed_outcome": observed_outcome,
        "status": status,
        "coverage": float(coverage),
        "evidence_digest": _digest(evidence_digest, "evidence_digest"),
        "issued_at": timestamp.isoformat(),
    }
    digest = receipt_digest(payload)
    signature = await sign_digest(digest, purpose="COMPLIANCE")
    return EffectivenessReceipt(
        tenant_id=str(tenant_id),
        assessment_id=str(assessment_id),
        control_id=control_id,
        probe_id=probe_id,
        probe_version=probe_version,
        scope_digest=payload["scope_digest"],
        input_digest=payload["input_digest"],
        observations=observations,
        expected_outcome=expected_outcome,
        observed_outcome=observed_outcome,
        status=status,
        coverage=float(coverage),
        evidence_digest=payload["evidence_digest"],
        signer_key_id=signature.kid,
        signature_b64=signature.signature_b64,
        receipt_digest=digest,
        issued_at=timestamp.astimezone(UTC),
    )


async def verify_effectiveness_receipt(receipt: EffectivenessReceipt) -> bool:
    """Verify canonical content and Ed25519 signature using the COMPLIANCE key domain."""
    try:
        validate_receipt_fields(
            tenant_id=receipt.tenant_id,
            assessment_id=receipt.assessment_id,
            control_id=receipt.control_id,
            probe_id=receipt.probe_id,
            probe_version=receipt.probe_version,
            scope_digest=receipt.scope_digest,
            input_digest=receipt.input_digest,
            observations=receipt.observations,
            expected_outcome=receipt.expected_outcome,
            observed_outcome=receipt.observed_outcome,
            status=receipt.status,
            coverage=receipt.coverage,
            evidence_digest=receipt.evidence_digest,
        )
        if not receipt.signer_key_id or not receipt.signature_b64:
            return False
        digest = receipt_digest(receipt.signed_payload())
        if digest != receipt.receipt_digest:
            return False
        return await verify_digest_signature(
            digest,
            receipt.signature_b64,
            receipt.signer_key_id,
            purpose="COMPLIANCE",
        )
    except (EffectivenessReceiptError, TypeError, ValueError):
        return False
