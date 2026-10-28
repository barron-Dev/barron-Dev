from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.ai.action_verifier import (
    GENESIS_HASH,
    sign_action_envelope,
    verify_action_chain,
    verify_action_envelope,
)


def _context():
    private = Ed25519PrivateKey.generate()
    keys = {"ai-action-key-1": private.public_key()}
    tenant_id, run_id, agent_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    return private, keys, tenant_id, run_id, agent_id


def _sign(private, tenant_id, run_id, agent_id, **kwargs):
    defaults = dict(
        tenant_id=tenant_id, run_id=run_id, agent_id=agent_id,
        actor_id="service-worker-1", action_type="tool.execute",
        payload={"tool": "lookup", "args": {"target": "example.test"}},
        signer_key_id="ai-action-key-1", signing_key=private,
        occurred_at=datetime(2026, 10, 28, 3, 0, 0, tzinfo=UTC),
    )
    defaults.update(kwargs)
    return sign_action_envelope(**defaults)


def test_valid_action_receipt_recomputes_payload_event_and_signature():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    result = verify_action_envelope(
        envelope, public_keys=keys, expected_tenant_id=tenant, expected_run_id=run,
    )
    assert result.ok is True
    assert result.reason == "verified"
    assert result.payload_hash == envelope.payload_hash
    assert result.event_hash == envelope.event_hash


def test_payload_tampering_is_detected_even_when_hash_field_is_unchanged():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    changed = replace(
        envelope,
        payload_canonical='{"args":{"target":"evil.test"},"tool":"lookup"}',
    )
    result = verify_action_envelope(changed, public_keys=keys)
    assert not result.ok
    assert result.reason == "payload_hash_mismatch"


def test_noncanonical_payload_and_duplicate_keys_are_rejected():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    noncanonical = replace(
        envelope,
        payload_canonical='{"tool": "lookup", "args": {"target": "example.test"}}',
    )
    assert verify_action_envelope(noncanonical, public_keys=keys).reason == "payload_not_canonical"
    duplicate = replace(envelope, payload_canonical='{"tool":"a","tool":"b"}')
    assert verify_action_envelope(duplicate, public_keys=keys).reason == "payload_json_invalid"


def test_event_metadata_tampering_is_detected():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    changed = replace(envelope, action_type="tool.delete")
    assert verify_action_envelope(changed, public_keys=keys).reason == "event_hash_mismatch"


def test_invalid_signature_and_unknown_signer_fail_closed():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    signature = ("0" if envelope.signature_hex[0] != "0" else "1") + envelope.signature_hex[1:]
    assert verify_action_envelope(
        replace(envelope, signature_hex=signature), public_keys=keys,
    ).reason == "signature_invalid"
    assert verify_action_envelope(envelope, public_keys={}).reason == "signer_key_unknown"


def test_tenant_and_run_binding_are_enforced():
    private, keys, tenant, run, agent = _context()
    envelope = _sign(private, tenant, run, agent)
    assert verify_action_envelope(
        envelope, public_keys=keys, expected_tenant_id=str(uuid.uuid4()),
    ).reason == "tenant_binding_mismatch"
    assert verify_action_envelope(
        envelope, public_keys=keys, expected_run_id=str(uuid.uuid4()),
    ).reason == "run_binding_mismatch"


def test_chain_checks_sequence_and_previous_hash():
    private, keys, tenant, run, agent = _context()
    first = _sign(private, tenant, run, agent, sequence=1, previous_hash=GENESIS_HASH)
    second = _sign(
        private, tenant, run, agent, sequence=2, previous_hash=first.event_hash,
        payload={"decision": "deny"},
    )
    good = verify_action_chain(
        [first, second], public_keys=keys,
        expected_tenant_id=tenant, expected_run_id=run,
    )
    assert good.ok and good.checked_events == 2
    bad_link = replace(second, previous_hash=GENESIS_HASH)
    bad = verify_action_chain([first, bad_link], public_keys=keys)
    assert not bad.ok and bad.reason == "previous_hash_mismatch"
    bad_sequence = replace(second, sequence=3)
    gap = verify_action_chain([first, bad_sequence], public_keys=keys)
    assert not gap.ok and gap.reason == "sequence_mismatch"


def test_naive_timestamp_and_non_json_payload_are_rejected():
    private, _, tenant, run, agent = _context()
    try:
        _sign(private, tenant, run, agent, occurred_at=datetime(2026, 10, 28))
        assert False, "naive timestamp should be rejected"
    except ValueError as exc:
        assert "timezone_aware" in str(exc)
    try:
        _sign(private, tenant, run, agent, payload={"value": float("nan")})
        assert False, "NaN should be rejected"
    except ValueError:
        pass
