"""Cryptographically verifiable Watchtower evidence journal primitives.

This module creates signed, canonical event envelopes and verifies a chain.
It is intentionally a primitive, not a persistence layer: callers must commit
records transactionally to durable tenant-scoped storage and protect signing
keys in a KMS/HSM before claiming production auditability.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_GENESIS_HASH = "0" * 64


class JournalValidationError(ValueError):
    """An evidence record is malformed or fails chain verification."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JournalValidationError("payload_must_be_finite_json") from exc


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise JournalValidationError("recorded_at_must_be_timezone_aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _digest_hex(value: str, field: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise JournalValidationError(f"{field}_must_be_lowercase_sha256")


@dataclass(frozen=True, slots=True)
class SignedEvidenceRecord:
    schema: str
    tenant_id: str
    journal_id: str
    sequence: int
    recorded_at: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    signer_key_id: str
    public_key_hex: str
    record_hash: str
    signature_hex: str

    def unsigned_envelope(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "journal_id": self.journal_id,
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "signer_key_id": self.signer_key_id,
            "public_key_hex": self.public_key_hex,
        }


def create_signed_record(
    *,
    private_key: Ed25519PrivateKey,
    tenant_id: str,
    journal_id: str,
    sequence: int,
    recorded_at: datetime,
    event_type: str,
    payload: dict[str, Any],
    previous_hash: str = _GENESIS_HASH,
    signer_key_id: str,
) -> SignedEvidenceRecord:
    """Create one Ed25519-signed record; persistence/locking is caller-owned."""
    for field, value in (
        ("tenant_id", tenant_id), ("journal_id", journal_id),
        ("event_type", event_type), ("signer_key_id", signer_key_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise JournalValidationError(f"{field}_required")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise JournalValidationError("sequence_must_be_positive_integer")
    if not isinstance(payload, dict):
        raise JournalValidationError("payload_must_be_object")
    _digest_hex(previous_hash, "previous_hash")
    timestamp = _utc_timestamp(recorded_at)
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    envelope = {
        "schema": "cyclothone.watchtower.signed-evidence.v1",
        "tenant_id": tenant_id,
        "journal_id": journal_id,
        "sequence": sequence,
        "recorded_at": timestamp,
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash,
        "signer_key_id": signer_key_id,
        "public_key_hex": public_bytes.hex(),
    }
    envelope_bytes = _canonical_json(envelope)
    record_hash = hashlib.sha256(envelope_bytes).hexdigest()
    signature = private_key.sign(bytes.fromhex(record_hash))
    return SignedEvidenceRecord(
        schema=envelope["schema"], tenant_id=tenant_id, journal_id=journal_id,
        sequence=sequence, recorded_at=timestamp, event_type=event_type,
        payload=payload, previous_hash=previous_hash, signer_key_id=signer_key_id,
        public_key_hex=public_bytes.hex(), record_hash=record_hash,
        signature_hex=signature.hex(),
    )


def verify_signed_record(
    record: SignedEvidenceRecord,
    *,
    trusted_public_keys: dict[str, Ed25519PublicKey] | None = None,
) -> None:
    """Verify canonical content, hash, signature, and optional trusted key binding."""
    if record.schema != "cyclothone.watchtower.signed-evidence.v1":
        raise JournalValidationError("unsupported_record_schema")
    _digest_hex(record.previous_hash, "previous_hash")
    _digest_hex(record.record_hash, "record_hash")
    if not isinstance(record.signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", record.signature_hex):
        raise JournalValidationError("signature_must_be_ed25519_hex")
    if not isinstance(record.public_key_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", record.public_key_hex):
        raise JournalValidationError("public_key_must_be_ed25519_hex")
    envelope_bytes = _canonical_json(record.unsigned_envelope())
    expected_hash = hashlib.sha256(envelope_bytes).hexdigest()
    if expected_hash != record.record_hash:
        raise JournalValidationError("record_hash_mismatch")
    try:
        embedded = Ed25519PublicKey.from_public_bytes(bytes.fromhex(record.public_key_hex))
        if trusted_public_keys is not None:
            trusted = trusted_public_keys.get(record.signer_key_id)
            if trusted is None:
                raise JournalValidationError("signer_key_not_trusted")
            trusted_bytes = trusted.public_bytes(Encoding.Raw, PublicFormat.Raw)
            if trusted_bytes.hex() != record.public_key_hex:
                raise JournalValidationError("signer_key_binding_mismatch")
            embedded = trusted
        embedded.verify(bytes.fromhex(record.signature_hex), bytes.fromhex(record.record_hash))
    except InvalidSignature as exc:
        raise JournalValidationError("signature_invalid") from exc
    except ValueError as exc:
        raise JournalValidationError("public_key_or_signature_invalid") from exc


def verify_chain(
    records: Iterable[SignedEvidenceRecord],
    *,
    tenant_id: str,
    journal_id: str,
    trusted_public_keys: dict[str, Ed25519PublicKey] | None = None,
) -> int:
    """Verify an ordered contiguous journal; return the number of verified records."""
    if not tenant_id.strip() or not journal_id.strip():
        raise JournalValidationError("tenant_and_journal_required")
    expected_sequence = 1
    expected_previous = _GENESIS_HASH
    count = 0
    for record in records:
        if record.tenant_id != tenant_id or record.journal_id != journal_id:
            raise JournalValidationError("cross_tenant_or_journal_record")
        if record.sequence != expected_sequence:
            raise JournalValidationError("journal_sequence_gap_or_replay")
        if record.previous_hash != expected_previous:
            raise JournalValidationError("journal_previous_hash_mismatch")
        verify_signed_record(record, trusted_public_keys=trusted_public_keys)
        expected_previous = record.record_hash
        expected_sequence += 1
        count += 1
    return count
