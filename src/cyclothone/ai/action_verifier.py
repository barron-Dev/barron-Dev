from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64
PROTOCOL = "cyclothone.ai-action.v1"
_EVENT_DOMAIN = b"cyclothone.ai-action.event.v1:"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_128 = re.compile(r"^[0-9a-f]{128}$")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _validate_canonical_value(value: Any) -> None:
    """Restrict values to a cross-runtime profile that PostgreSQL can reproduce."""
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("json_object_keys_must_be_strings")
        for item in value.values():
            _validate_canonical_value(item)
    elif isinstance(value, list):
        for item in value:
            _validate_canonical_value(item)
    elif isinstance(value, float):
        # JSONB numeric formatting can differ from Python's exponent formatting.
        # Decimal quantities must be encoded as strings in this protocol.
        raise ValueError("floating_point_numbers_not_supported")
    elif value is None or isinstance(value, (str, int, bool)):
        return
    else:
        raise TypeError("unsupported_canonical_json_value")


def canonical_json(value: Any) -> str:
    """Return stable UTF-8 JSON under the cross-runtime canonical profile."""
    _validate_canonical_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_timestamp(value: datetime | None) -> str:
    stamp = value or datetime.now(UTC)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_uuid(value: str, field: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"{field}_must_be_uuid") from exc


def _frame(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded


def _event_hash(
    *,
    sequence: int,
    event_id: str,
    tenant_id: str,
    run_id: str,
    actor_id: str,
    agent_id: str | None,
    action_type: str,
    payload_hash: str,
    previous_hash: str,
    signer_key_id: str,
    occurred_at: str,
) -> str:
    # Length framing makes field boundaries unambiguous. The SQL migration uses
    # the same byte-length framing and field order.
    fields = (
        str(sequence), event_id, tenant_id, run_id, actor_id, agent_id or "",
        action_type, payload_hash, previous_hash, signer_key_id, occurred_at,
    )
    return sha256_hex(_EVENT_DOMAIN + b"".join(_frame(field) for field in fields))


@dataclass(frozen=True, slots=True)
class ActionEnvelope:
    protocol: str
    sequence: int
    event_id: str
    tenant_id: str
    run_id: str
    actor_id: str
    agent_id: str | None
    action_type: str
    payload_canonical: str
    payload_hash: str
    previous_hash: str
    event_hash: str
    signer_key_id: str
    signature_hex: str
    occurred_at: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "signer_key_id": self.signer_key_id,
            "occurred_at": self.occurred_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signed_fields(),
            "payload_canonical": self.payload_canonical,
            "event_hash": self.event_hash,
            "signature_hex": self.signature_hex,
        }


@dataclass(frozen=True, slots=True)
class ActionVerificationResult:
    ok: bool
    reason: str
    payload_hash: str | None = None
    event_hash: str | None = None
    signer_key_id: str | None = None
    sequence: int | None = None


@dataclass(frozen=True, slots=True)
class ActionChainVerificationResult:
    ok: bool
    checked_events: int
    reason: str
    failing_sequence: int | None
    head_hash: str


def sign_action_envelope(
    *,
    tenant_id: str,
    run_id: str,
    actor_id: str,
    action_type: str,
    payload: Any,
    signer_key_id: str,
    signing_key: Ed25519PrivateKey,
    agent_id: str | None = None,
    sequence: int = 1,
    previous_hash: str = GENESIS_HASH,
    event_id: str | None = None,
    occurred_at: datetime | None = None,
) -> ActionEnvelope:
    """Create an action receipt using a caller-owned Ed25519 key.

    Key custody is outside this primitive. In the service, signing must happen
    in a trusted backend/key provider, never in an untrusted model or browser.
    """
    if sequence < 1:
        raise ValueError("sequence_must_be_positive")
    if not isinstance(actor_id, str) or not actor_id.strip():
        raise ValueError("actor_id_required")
    if not isinstance(action_type, str) or not action_type.strip():
        raise ValueError("action_type_required")
    if not isinstance(signer_key_id, str) or not signer_key_id.strip():
        raise ValueError("signer_key_id_required")
    if not _HEX_64.fullmatch(previous_hash):
        raise ValueError("previous_hash_must_be_sha256_hex")

    tenant = _require_uuid(tenant_id, "tenant_id")
    run = _require_uuid(run_id, "run_id")
    event = _require_uuid(event_id or str(uuid.uuid4()), "event_id")
    agent = _require_uuid(agent_id, "agent_id") if agent_id else None
    payload_text = canonical_json(payload)
    payload_hash = sha256_hex(payload_text.encode("utf-8"))
    timestamp = _canonical_timestamp(occurred_at)
    event_hash = _event_hash(
        sequence=sequence,
        event_id=event,
        tenant_id=tenant,
        run_id=run,
        actor_id=actor_id,
        agent_id=agent,
        action_type=action_type,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        signer_key_id=signer_key_id,
        occurred_at=timestamp,
    )
    signature = signing_key.sign(event_hash.encode("ascii")).hex()
    return ActionEnvelope(
        protocol=PROTOCOL,
        sequence=sequence,
        event_id=event,
        tenant_id=tenant,
        run_id=run,
        actor_id=actor_id,
        agent_id=agent,
        action_type=action_type,
        payload_canonical=payload_text,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        event_hash=event_hash,
        signer_key_id=signer_key_id,
        signature_hex=signature,
        occurred_at=timestamp,
    )


def verify_action_envelope(
    envelope: ActionEnvelope,
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
    expected_tenant_id: str | None = None,
    expected_run_id: str | None = None,
    expected_previous_hash: str | None = None,
    expected_sequence: int | None = None,
) -> ActionVerificationResult:
    """Recompute payload/event hashes and verify Ed25519; fail closed on errors."""
    def fail(reason: str) -> ActionVerificationResult:
        return ActionVerificationResult(
            False, reason, envelope.payload_hash, envelope.event_hash,
            envelope.signer_key_id, envelope.sequence,
        )

    if envelope.protocol != PROTOCOL:
        return fail("unsupported_protocol")
    if envelope.sequence < 1:
        return fail("invalid_sequence")
    if not _HEX_64.fullmatch(envelope.payload_hash):
        return fail("invalid_payload_hash_format")
    if not _HEX_64.fullmatch(envelope.previous_hash):
        return fail("invalid_previous_hash_format")
    if not _HEX_64.fullmatch(envelope.event_hash):
        return fail("invalid_event_hash_format")
    if not _HEX_128.fullmatch(envelope.signature_hex):
        return fail("invalid_signature_format")
    try:
        if expected_tenant_id is not None and envelope.tenant_id != str(uuid.UUID(expected_tenant_id)):
            return fail("tenant_binding_mismatch")
        if expected_run_id is not None and envelope.run_id != str(uuid.UUID(expected_run_id)):
            return fail("run_binding_mismatch")
    except (ValueError, TypeError, AttributeError):
        return fail("invalid_expected_binding")
    if expected_previous_hash is not None and envelope.previous_hash != expected_previous_hash:
        return fail("previous_hash_mismatch")
    if expected_sequence is not None and envelope.sequence != expected_sequence:
        return fail("sequence_mismatch")

    try:
        parsed = json.loads(
            envelope.payload_canonical,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_constant")),
        )
        if canonical_json(parsed) != envelope.payload_canonical:
            return fail("payload_not_canonical")
        computed_payload_hash = sha256_hex(envelope.payload_canonical.encode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fail("payload_json_invalid")
    if computed_payload_hash != envelope.payload_hash:
        return fail("payload_hash_mismatch")

    computed_event_hash = _event_hash(
        sequence=envelope.sequence,
        event_id=envelope.event_id,
        tenant_id=envelope.tenant_id,
        run_id=envelope.run_id,
        actor_id=envelope.actor_id,
        agent_id=envelope.agent_id,
        action_type=envelope.action_type,
        payload_hash=computed_payload_hash,
        previous_hash=envelope.previous_hash,
        signer_key_id=envelope.signer_key_id,
        occurred_at=envelope.occurred_at,
    )
    if computed_event_hash != envelope.event_hash:
        return fail("event_hash_mismatch")
    key = public_keys.get(envelope.signer_key_id)
    if key is None:
        return fail("signer_key_unknown")
    try:
        key.verify(bytes.fromhex(envelope.signature_hex), computed_event_hash.encode("ascii"))
    except (InvalidSignature, ValueError, TypeError):
        return fail("signature_invalid")
    return ActionVerificationResult(
        True, "verified", computed_payload_hash, computed_event_hash,
        envelope.signer_key_id, envelope.sequence,
    )


def verify_action_chain(
    envelopes: list[ActionEnvelope] | tuple[ActionEnvelope, ...],
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
    expected_tenant_id: str | None = None,
    expected_run_id: str | None = None,
) -> ActionChainVerificationResult:
    previous = GENESIS_HASH
    expected_sequence = 1
    for envelope in envelopes:
        result = verify_action_envelope(
            envelope,
            public_keys=public_keys,
            expected_tenant_id=expected_tenant_id,
            expected_run_id=expected_run_id,
            expected_previous_hash=previous,
            expected_sequence=expected_sequence,
        )
        if not result.ok:
            return ActionChainVerificationResult(
                False, expected_sequence - 1, result.reason, envelope.sequence, previous,
            )
        previous = envelope.event_hash
        expected_sequence += 1
    return ActionChainVerificationResult(True, len(envelopes), "verified", None, previous)
