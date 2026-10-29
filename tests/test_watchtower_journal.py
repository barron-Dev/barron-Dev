from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.watchtower.journal import (
    JournalValidationError,
    create_signed_record,
    verify_chain,
    verify_signed_record,
)


def _chain():
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 10, 29, 8, 0, tzinfo=timezone.utc)
    first = create_signed_record(
        private_key=key,
        tenant_id="tenant-a",
        journal_id="room-camera-journal",
        sequence=1,
        recorded_at=now,
        event_type="camera.frame_observed",
        payload={"camera_id": "camera-1", "frame_sha256": "a" * 64},
        signer_key_id="edge-key-1",
    )
    second = create_signed_record(
        private_key=key,
        tenant_id="tenant-a",
        journal_id="room-camera-journal",
        sequence=2,
        recorded_at=now + timedelta(seconds=1),
        event_type="camera.coverage_updated",
        payload={"coverage": "partial_coverage", "reason": "source_gap"},
        previous_hash=first.record_hash,
        signer_key_id="edge-key-1",
    )
    return key, first, second


def test_signed_chain_verifies_with_explicit_trusted_key():
    key, first, second = _chain()
    assert verify_chain(
        [first, second],
        tenant_id="tenant-a",
        journal_id="room-camera-journal",
        trusted_public_keys={"edge-key-1": key.public_key()},
    ) == 2


def test_record_payload_tampering_is_detected():
    _, first, _ = _chain()
    tampered = replace(first, payload={"camera_id": "camera-1", "frame_sha256": "b" * 64})
    with pytest.raises(JournalValidationError, match="record_hash_mismatch"):
        verify_signed_record(tampered)


def test_chain_rejects_cross_tenant_records():
    key, first, second = _chain()
    cross_tenant = replace(second, tenant_id="tenant-b")
    with pytest.raises(JournalValidationError, match="cross_tenant"):
        verify_chain([first, cross_tenant], tenant_id="tenant-a", journal_id="room-camera-journal")


def test_chain_rejects_sequence_gaps_and_wrong_previous_hash():
    _, first, second = _chain()
    with pytest.raises(JournalValidationError, match="sequence_gap"):
        verify_chain([first, replace(second, sequence=3)], tenant_id="tenant-a", journal_id="room-camera-journal")
    with pytest.raises(JournalValidationError, match="previous_hash_mismatch"):
        verify_chain([first, replace(second, previous_hash="0" * 64)], tenant_id="tenant-a", journal_id="room-camera-journal")


def test_chain_rejects_untrusted_or_mismatched_signer_key():
    key, first, _ = _chain()
    other_key = Ed25519PrivateKey.generate()
    with pytest.raises(JournalValidationError, match="signer_key_not_trusted"):
        verify_signed_record(first, trusted_public_keys={"other-key": other_key.public_key()})
    with pytest.raises(JournalValidationError, match="signer_key_binding_mismatch"):
        verify_signed_record(first, trusted_public_keys={"edge-key-1": other_key.public_key()})


def test_payload_must_be_finite_json_and_timestamp_timezone_aware():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(JournalValidationError, match="payload_must_be_finite_json"):
        create_signed_record(
            private_key=key, tenant_id="tenant-a", journal_id="j", sequence=1,
            recorded_at=datetime.now(timezone.utc), event_type="event",
            payload={"invalid": float("nan")}, signer_key_id="key",
        )
    with pytest.raises(JournalValidationError, match="timezone_aware"):
        create_signed_record(
            private_key=key, tenant_id="tenant-a", journal_id="j", sequence=1,
            recorded_at=datetime(2026, 10, 29), event_type="event",
            payload={}, signer_key_id="key",
        )
