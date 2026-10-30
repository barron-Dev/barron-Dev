from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from cyclothone.compliance.effectiveness import EffectivenessReceipt
from cyclothone.compliance.receipt_store import receipt_from_row, receipt_to_row


def _receipt() -> EffectivenessReceipt:
    return EffectivenessReceipt(
        tenant_id=str(uuid4()),
        assessment_id=str(uuid4()),
        control_id="soc2.CC7.1",
        probe_id="logging-integrity",
        probe_version="1.0.0",
        scope_digest="a" * 64,
        input_digest="b" * 64,
        observations={"events_checked": 12, "nested": {"tamper_detected": True}},
        expected_outcome="tampering_detected",
        observed_outcome="tampering_detected",
        status="effective",
        coverage=1.0,
        evidence_digest="c" * 64,
        signer_key_id="compliance-key-1",
        signature_b64="c2lnbmF0dXJl",
        receipt_digest="d" * 64,
        issued_at=datetime(2026, 10, 30, 5, 0, tzinfo=UTC),
    )


def test_receipt_persistence_mapping_round_trips_signed_fields():
    original = _receipt()
    row = receipt_to_row(original)
    restored = receipt_from_row(row)
    assert restored.signed_payload() == original.signed_payload()
    assert restored.signature_b64 == original.signature_b64
    assert restored.signer_key_id == original.signer_key_id
    assert restored.receipt_digest == original.receipt_digest


def test_receipt_persistence_mapping_preserves_nested_observations():
    row = receipt_to_row(_receipt())
    restored = receipt_from_row(row)
    assert restored.observations["nested"]["tamper_detected"] is True
