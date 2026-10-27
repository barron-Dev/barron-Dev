from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64
_EVENT_DOMAIN = b"cyclothone.contract-journal.event.v1\0"
_CHECKPOINT_DOMAIN = b"cyclothone.contract-journal.checkpoint.v1\0"


def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically; reject NaN/Infinity and non-JSON values."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp(value: datetime | None) -> str:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _event_body(
    *,
    sequence: int,
    event_id: str,
    tenant_id: str,
    actor_id: str,
    agent_id: str | None,
    action_type: str,
    payload_hash: str,
    previous_hash: str,
    occurred_at: str,
    signer_key_id: str,
) -> dict[str, Any]:
    return {
        "protocol": "cyclothone.contract-journal.event.v1",
        "sequence": sequence,
        "event_id": event_id,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "agent_id": agent_id,
        "action_type": action_type,
        "payload_hash": payload_hash,
        "previous_hash": previous_hash,
        "occurred_at": occurred_at,
        "signer_key_id": signer_key_id,
    }


def _event_digest(body: Mapping[str, Any]) -> str:
    return sha256_hex(_EVENT_DOMAIN + canonical_json(body))


@dataclass(frozen=True)
class JournalEvent:
    sequence: int
    event_id: str
    tenant_id: str
    actor_id: str
    agent_id: str | None
    action_type: str
    payload_hash: str
    payload_json: str | None
    previous_hash: str
    event_hash: str
    signer_key_id: str
    signature_hex: str
    occurred_at: str


@dataclass(frozen=True)
class JournalCheckpoint:
    protocol: str
    node_id: str
    sequence: int
    root_hash: str
    created_at: str
    signer_key_id: str
    signature_hex: str

    def signed_body(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "node_id": self.node_id,
            "sequence": self.sequence,
            "root_hash": self.root_hash,
            "created_at": self.created_at,
            "signer_key_id": self.signer_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_body(), "signature_hex": self.signature_hex}


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    checked_events: int
    head_sequence: int
    head_hash: str
    reason: str


class LocalContractJournal:
    """SQLite-backed, signed hash-chain journal for offline execution evidence.

    Private signing keys are supplied by the caller and are never stored in SQLite.
    This class is a local journal primitive, not an HSM/TEE implementation or a
    remote checkpoint/anchor service. Keep payloads minimized; by default only the
    canonical payload hash is persisted.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=10000")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
        self._initialize()

    def _initialize(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS contract_journal_events (
                sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                event_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                agent_id TEXT,
                action_type TEXT NOT NULL,
                payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
                payload_json TEXT,
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
                signer_key_id TEXT NOT NULL,
                signature_hex TEXT NOT NULL CHECK (length(signature_hex) = 128),
                occurred_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS contract_journal_no_update
            BEFORE UPDATE ON contract_journal_events
            BEGIN SELECT RAISE(ABORT, 'contract_journal_events_are_immutable'); END;
            CREATE TRIGGER IF NOT EXISTS contract_journal_no_delete
            BEFORE DELETE ON contract_journal_events
            BEGIN SELECT RAISE(ABORT, 'contract_journal_events_are_immutable'); END;
            """
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def append_event(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        action_type: str,
        payload: Any,
        signer_key_id: str,
        signing_key: Ed25519PrivateKey,
        agent_id: str | None = None,
        occurred_at: datetime | None = None,
        persist_payload: bool = False,
    ) -> JournalEvent:
        required = {
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "action_type": action_type,
            "signer_key_id": signer_key_id,
        }
        if any(not isinstance(value, str) or not value.strip() for value in required.values()):
            raise ValueError("tenant_actor_action_and_signer_are_required")
        if agent_id is not None and (not isinstance(agent_id, str) or not agent_id.strip()):
            raise ValueError("agent_id_must_be_nonempty_when_supplied")

        payload_bytes = canonical_json(payload)
        payload_hash = sha256_hex(payload_bytes)
        payload_json = payload_bytes.decode("utf-8") if persist_payload else None
        timestamp = _timestamp(occurred_at)
        event_id = str(uuid.uuid4())

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                previous = self._db.execute(
                    "SELECT sequence, event_hash FROM contract_journal_events "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if previous is None else int(previous["sequence"]) + 1
                previous_hash = GENESIS_HASH if previous is None else str(previous["event_hash"])
                body = _event_body(
                    sequence=sequence,
                    event_id=event_id,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    agent_id=agent_id,
                    action_type=action_type,
                    payload_hash=payload_hash,
                    previous_hash=previous_hash,
                    occurred_at=timestamp,
                    signer_key_id=signer_key_id,
                )
                event_hash = _event_digest(body)
                signature_hex = signing_key.sign(event_hash.encode("ascii")).hex()
                self._db.execute(
                    """
                    INSERT INTO contract_journal_events (
                        sequence, event_id, tenant_id, actor_id, agent_id, action_type,
                        payload_hash, payload_json, previous_hash, event_hash,
                        signer_key_id, signature_hex, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sequence, event_id, tenant_id, actor_id, agent_id, action_type,
                        payload_hash, payload_json, previous_hash, event_hash,
                        signer_key_id, signature_hex, timestamp,
                    ),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

        return JournalEvent(
            sequence=sequence,
            event_id=event_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            agent_id=agent_id,
            action_type=action_type,
            payload_hash=payload_hash,
            payload_json=payload_json,
            previous_hash=previous_hash,
            event_hash=event_hash,
            signer_key_id=signer_key_id,
            signature_hex=signature_hex,
            occurred_at=timestamp,
        )

    def events(self) -> list[JournalEvent]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM contract_journal_events ORDER BY sequence"
            ).fetchall()
        return [JournalEvent(**dict(row)) for row in rows]

    def checkpoint(
        self,
        *,
        node_id: str,
        signer_key_id: str,
        signing_key: Ed25519PrivateKey,
        created_at: datetime | None = None,
    ) -> JournalCheckpoint:
        if not node_id.strip() or not signer_key_id.strip():
            raise ValueError("node_and_signer_key_ids_are_required")
        timestamp = _timestamp(created_at)
        with self._lock:
            row = self._db.execute(
                "SELECT sequence, event_hash FROM contract_journal_events "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        sequence = 0 if row is None else int(row["sequence"])
        root_hash = GENESIS_HASH if row is None else str(row["event_hash"])
        checkpoint = JournalCheckpoint(
            protocol="cyclothone.contract-journal.checkpoint.v1",
            node_id=node_id,
            sequence=sequence,
            root_hash=root_hash,
            created_at=timestamp,
            signer_key_id=signer_key_id,
            signature_hex="",
        )
        signature = signing_key.sign(
            _CHECKPOINT_DOMAIN + canonical_json(checkpoint.signed_body())
        ).hex()
        return JournalCheckpoint(**{**checkpoint.__dict__, "signature_hex": signature})

    @staticmethod
    def verify_checkpoint(
        checkpoint: JournalCheckpoint,
        public_keys: Mapping[str, Ed25519PublicKey],
    ) -> bool:
        if checkpoint.protocol != "cyclothone.contract-journal.checkpoint.v1":
            return False
        if checkpoint.sequence < 0 or len(checkpoint.root_hash) != 64:
            return False
        key = public_keys.get(checkpoint.signer_key_id)
        if key is None:
            return False
        try:
            key.verify(
                bytes.fromhex(checkpoint.signature_hex),
                _CHECKPOINT_DOMAIN + canonical_json(checkpoint.signed_body()),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    def verify_chain(
        self,
        *,
        public_keys: Mapping[str, Ed25519PublicKey],
        checkpoint: JournalCheckpoint | None = None,
    ) -> VerificationResult:
        rows = self.events()
        previous_hash = GENESIS_HASH
        expected_sequence = 1
        for row in rows:
            if row.sequence != expected_sequence:
                return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "sequence_gap")
            if row.previous_hash != previous_hash:
                return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "previous_hash_mismatch")
            try:
                if row.payload_json is not None:
                    stored_payload_hash = sha256_hex(canonical_json(json.loads(row.payload_json)))
                    if stored_payload_hash != row.payload_hash:
                        return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "payload_hash_mismatch")
                body = _event_body(
                    sequence=row.sequence,
                    event_id=row.event_id,
                    tenant_id=row.tenant_id,
                    actor_id=row.actor_id,
                    agent_id=row.agent_id,
                    action_type=row.action_type,
                    payload_hash=row.payload_hash,
                    previous_hash=row.previous_hash,
                    occurred_at=row.occurred_at,
                    signer_key_id=row.signer_key_id,
                )
                calculated_hash = _event_digest(body)
                if calculated_hash != row.event_hash:
                    return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "event_hash_mismatch")
                key = public_keys.get(row.signer_key_id)
                if key is None:
                    return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "unknown_signing_key")
                key.verify(bytes.fromhex(row.signature_hex), row.event_hash.encode("ascii"))
            except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError):
                return VerificationResult(False, expected_sequence - 1, row.sequence, previous_hash, "signature_or_encoding_invalid")
            previous_hash = row.event_hash
            expected_sequence += 1

        head_sequence = expected_sequence - 1
        head_hash = previous_hash
        if checkpoint is not None:
            if not self.verify_checkpoint(checkpoint, public_keys):
                return VerificationResult(False, len(rows), head_sequence, head_hash, "checkpoint_signature_invalid")
            if checkpoint.sequence > head_sequence:
                return VerificationResult(False, len(rows), head_sequence, head_hash, "checkpoint_ahead_of_local_journal")
            checkpoint_hash = GENESIS_HASH
            if checkpoint.sequence:
                checkpoint_hash = rows[checkpoint.sequence - 1].event_hash
            if checkpoint_hash != checkpoint.root_hash:
                return VerificationResult(False, len(rows), head_sequence, head_hash, "checkpoint_root_mismatch")
        return VerificationResult(True, len(rows), head_sequence, head_hash, "verified")
