from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyclothone.journal.local import LocalContractJournal


def _keys():
    private = Ed25519PrivateKey.generate()
    return private, {"edge-key-1": private.public_key()}


def _append(journal, private, *, payload=None, persist_payload=False):
    return journal.append_event(
        tenant_id="tenant-a",
        actor_id="analyst-7",
        agent_id="edge-agent-1",
        action_type="tool.execute",
        payload={"tool": "lookup", "args": {"target": "example.test"}} if payload is None else payload,
        signer_key_id="edge-key-1",
        signing_key=private,
        occurred_at=datetime(2026, 10, 27, tzinfo=timezone.utc),
        persist_payload=persist_payload,
    )


def test_append_creates_signed_contiguous_hash_chain():
    private, keys = _keys()
    journal = LocalContractJournal(":memory:")
    first = _append(journal, private)
    second = _append(journal, private, payload={"decision": "deny"})

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_hash == first.event_hash
    assert journal.verify_chain(public_keys=keys).ok
    journal.close()


def test_persisted_payload_is_checked_for_tampering(tmp_path):
    private, keys = _keys()
    path = tmp_path / "journal.sqlite"
    journal = LocalContractJournal(path)
    event = _append(journal, private, persist_payload=True)
    journal.close()

    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER contract_journal_no_update")
    raw.execute("UPDATE contract_journal_events SET payload_json='{"tool":"tampered"}' WHERE sequence=1")
    raw.commit()
    raw.close()

    reopened = LocalContractJournal(path)
    result = reopened.verify_chain(public_keys=keys)
    assert result.ok is False
    assert result.reason == "payload_hash_mismatch"
    reopened.close()


def test_update_and_delete_are_rejected_by_immutability_triggers():
    private, _ = _keys()
    journal = LocalContractJournal(":memory:")
    _append(journal, private)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        journal._db.execute("UPDATE contract_journal_events SET action_type='changed' WHERE sequence=1")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        journal._db.execute("DELETE FROM contract_journal_events WHERE sequence=1")
    journal.close()


def test_chain_verification_detects_modified_hash(tmp_path):
    private, keys = _keys()
    path = tmp_path / "journal.sqlite"
    journal = LocalContractJournal(path)
    _append(journal, private)
    journal.close()

    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER contract_journal_no_update")
    raw.execute("UPDATE contract_journal_events SET event_hash=? WHERE sequence=1", ("f" * 64,))
    raw.commit()
    raw.close()

    reopened = LocalContractJournal(path)
    result = reopened.verify_chain(public_keys=keys)
    assert result.ok is False
    assert result.reason == "event_hash_mismatch"
    reopened.close()


def test_signed_checkpoint_detects_truncated_history(tmp_path):
    private, keys = _keys()
    path = tmp_path / "journal.sqlite"
    journal = LocalContractJournal(path)
    _append(journal, private)
    checkpoint = journal.checkpoint(node_id="edge-1", signer_key_id="edge-key-1", signing_key=private)
    _append(journal, private, payload={"decision": "allow"})
    journal.close()

    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER contract_journal_no_delete")
    raw.execute("DELETE FROM contract_journal_events WHERE sequence=1")
    raw.commit()
    raw.close()

    reopened = LocalContractJournal(path)
    result = reopened.verify_chain(public_keys=keys, checkpoint=checkpoint)
    assert result.ok is False
    assert result.reason in {"sequence_gap", "checkpoint_ahead_of_local_journal", "checkpoint_root_mismatch"}
    reopened.close()


def test_checkpoint_signature_is_bound_to_root_and_sequence():
    private, keys = _keys()
    journal = LocalContractJournal(":memory:")
    _append(journal, private)
    checkpoint = journal.checkpoint(node_id="edge-1", signer_key_id="edge-key-1", signing_key=private)
    assert journal.verify_checkpoint(checkpoint, keys)

    altered = type(checkpoint)(
        protocol=checkpoint.protocol,
        node_id=checkpoint.node_id,
        sequence=checkpoint.sequence + 1,
        root_hash=checkpoint.root_hash,
        created_at=checkpoint.created_at,
        signer_key_id=checkpoint.signer_key_id,
        signature_hex=checkpoint.signature_hex,
    )
    assert not journal.verify_checkpoint(altered, keys)
    journal.close()


def test_non_utc_naive_timestamps_are_rejected():
    private, _ = _keys()
    journal = LocalContractJournal(":memory:")
    with pytest.raises(ValueError, match="timezone_aware"):
        _append(journal, private, payload={"x": 1})
        journal.append_event(
            tenant_id="tenant-a",
            actor_id="actor-a",
            action_type="test",
            payload={},
            signer_key_id="edge-key-1",
            signing_key=private,
            occurred_at=datetime(2026, 10, 27),
        )
    journal.close()
