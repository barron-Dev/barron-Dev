from __future__ import annotations

from uuid import uuid4

import pytest
from datetime import UTC, datetime, timedelta
from dataclasses import replace
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.compliance.signing import ComplianceSignature

from cyclothone.compliance.effectiveness import (
    EffectivenessReceiptError,
    create_effectiveness_receipt,
    receipt_digest,
    validate_receipt_fields,
    verify_effectiveness_receipt,
)


def _fields():
    digest = "a" * 64
    return {
        "tenant_id": str(uuid4()),
        "assessment_id": str(uuid4()),
        "control_id": "soc2.CC7.1",
        "probe_id": "logging-integrity",
        "probe_version": "1.0.0",
        "scope_digest": digest,
        "input_digest": "b" * 64,
        "observations": {"events_checked": 12, "tamper_detected": True},
        "expected_outcome": "tampering_detected",
        "observed_outcome": "tampering_detected",
        "status": "effective",
        "coverage": 1.0,
        "evidence_digest": "c" * 64,
    }


def test_receipt_digest_is_deterministic_for_mapping_order():
    first = {"tenant_id": "t", "observations": {"b": 2, "a": 1}}
    second = {"observations": {"a": 1, "b": 2}, "tenant_id": "t"}
    assert receipt_digest(first) == receipt_digest(second)


def test_valid_unknown_is_a_first_class_status():
    fields = _fields()
    fields["status"] = "unknown"
    fields["coverage"] = 0.0
    validate_receipt_fields(**fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "passing"),
        ("status", ["effective"]),
        ("coverage", 1.1),
        ("coverage", True),
        ("scope_digest", "not-a-digest"),
        ("input_digest", "f" * 63),
        ("evidence_digest", "x" * 64),
        ("observations", ["not", "an", "object"]),
    ],
)
def test_invalid_receipt_fields_fail_closed(field, value):
    fields = _fields()
    fields[field] = value
    with pytest.raises(EffectivenessReceiptError):
        validate_receipt_fields(**fields)


def test_receipt_payload_changes_when_scope_changes():
    fields = _fields()
    original = receipt_digest(fields)
    fields["scope_digest"] = "d" * 64
    assert receipt_digest(fields) != original


def test_non_finite_observation_values_are_rejected():
    fields = _fields()
    fields["observations"] = {"score": float("nan")}
    with pytest.raises(EffectivenessReceiptError):
        validate_receipt_fields(**fields)


@pytest.mark.asyncio
async def test_receipt_signature_binds_issuance_timestamp_and_compliance_key_domain():
    fields = _fields()
    issued_at = datetime(2026, 10, 30, 5, 0, tzinfo=UTC)
    with patch(
        "cyclothone.compliance.effectiveness.sign_digest",
        new=AsyncMock(return_value=ComplianceSignature("c2ln", "compliance-key-1")),
    ) as sign:
        receipt = await create_effectiveness_receipt(
            tenant_id=__import__("uuid").UUID(fields["tenant_id"]),
            assessment_id=__import__("uuid").UUID(fields["assessment_id"]),
            control_id=fields["control_id"],
            probe_id=fields["probe_id"],
            probe_version=fields["probe_version"],
            scope_digest=fields["scope_digest"],
            input_digest=fields["input_digest"],
            observations=fields["observations"],
            expected_outcome=fields["expected_outcome"],
            observed_outcome=fields["observed_outcome"],
            status=fields["status"],
            coverage=fields["coverage"],
            evidence_digest=fields["evidence_digest"],
            issued_at=issued_at,
        )
    sign.assert_awaited_once()
    assert sign.await_args.kwargs["purpose"] == "COMPLIANCE"
    assert receipt.issued_at == issued_at
    with patch(
        "cyclothone.compliance.effectiveness.verify_digest_signature",
        new=AsyncMock(return_value=True),
    ) as verify:
        assert await verify_effectiveness_receipt(receipt) is True
        tampered = replace(receipt, issued_at=issued_at + timedelta(seconds=1))
        assert await verify_effectiveness_receipt(tampered) is False
        verify.assert_awaited_once()


@pytest.mark.asyncio
async def test_receipt_uses_real_ed25519_signature_and_rejects_tampering():
    from cyclothone.compliance import signing

    fields = _fields()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    with (
        patch.dict("os.environ", {"CYCLOTHONE_COMPLIANCE_SIGNING_KID": "local-test-key"}),
        patch.object(signing.supabase, "select_one", new=AsyncMock(
            return_value={"kid": "local-test-key", "active": True, "purpose": "COMPLIANCE"}
        )),
        patch.object(signing, "_load_private_key", new=AsyncMock(return_value=private_key)),
        patch.object(signing, "_load_public_key", new=AsyncMock(return_value=public_key)),
    ):
        receipt = await create_effectiveness_receipt(
            tenant_id=__import__("uuid").UUID(fields["tenant_id"]),
            assessment_id=__import__("uuid").UUID(fields["assessment_id"]),
            control_id=fields["control_id"],
            probe_id=fields["probe_id"],
            probe_version=fields["probe_version"],
            scope_digest=fields["scope_digest"],
            input_digest=fields["input_digest"],
            observations=fields["observations"],
            expected_outcome=fields["expected_outcome"],
            observed_outcome=fields["observed_outcome"],
            status=fields["status"],
            coverage=fields["coverage"],
            evidence_digest=fields["evidence_digest"],
        )
        assert await verify_effectiveness_receipt(receipt) is True
        tampered = replace(receipt, observed_outcome="tampering_not_detected")
        assert await verify_effectiveness_receipt(tampered) is False


@pytest.mark.asyncio
async def test_receipt_observations_are_deeply_immutable_after_issuance():
    fields = _fields()
    observations = {"nested": {"events": [1, 2, 3]}}
    with patch(
        "cyclothone.compliance.effectiveness.sign_digest",
        new=AsyncMock(return_value=ComplianceSignature("c2ln", "compliance-key-1")),
    ):
        receipt = await create_effectiveness_receipt(
            tenant_id=__import__("uuid").UUID(fields["tenant_id"]),
            assessment_id=__import__("uuid").UUID(fields["assessment_id"]),
            control_id=fields["control_id"],
            probe_id=fields["probe_id"],
            probe_version=fields["probe_version"],
            scope_digest=fields["scope_digest"],
            input_digest=fields["input_digest"],
            observations=observations,
            expected_outcome=fields["expected_outcome"],
            observed_outcome=fields["observed_outcome"],
            status=fields["status"],
            coverage=fields["coverage"],
            evidence_digest=fields["evidence_digest"],
        )
    observations["nested"]["events"].append(4)
    assert receipt.observations["nested"]["events"] == (1, 2, 3)
    with pytest.raises(TypeError):
        receipt.observations["new"] = "mutation"
    with pytest.raises(TypeError):
        receipt.observations["nested"]["new"] = "mutation"
