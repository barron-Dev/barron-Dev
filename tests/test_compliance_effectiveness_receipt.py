from __future__ import annotations

from uuid import uuid4

import pytest

from cyclothone.compliance.effectiveness import (
    EffectivenessReceiptError,
    receipt_digest,
    validate_receipt_fields,
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
