"""Canonical, signed evidence events for Cyclothone Omni-Vision."""
import hashlib
import json
from collections.abc import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b"cyclothone:omni-vision:event:v1\0"
SIG_DOMAIN = b"cyclothone:omni-vision:signature:v1\0"
SCHEMA = "cyclothone.omni-vision.evidence.v1"


def canonical_json(value) -> bytes:
    """Stable JSON; non-finite numbers and non-JSON objects are rejected."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid canonical JSON value") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_media_bytes(media: bytes) -> str:
    """Hash exact bytes before any decoding or re-encoding."""
    if not isinstance(media, bytes):
        raise TypeError("media must be bytes")
    return sha256_hex(media)


def create_signed_event(payload: Mapping, key: Ed25519PrivateKey, *,
                        key_id: str, previous_event_hash: str | None = None) -> dict:
    """Sign an event envelope; private-key storage is caller-owned."""
    if not isinstance(payload, Mapping) or not key_id or len(key_id) > 200:
        raise ValueError("invalid payload or key_id")
    if previous_event_hash is not None and (
        len(previous_event_hash) != 64 or any(c not in "0123456789abcdef" for c in previous_event_hash)
    ):
        raise ValueError("invalid previous event hash")
    payload = dict(payload)
    payload_hash = sha256_hex(canonical_json(payload))
    body = {"schema_version": SCHEMA, "key_id": key_id,
            "previous_event_hash": previous_event_hash,
            "payload_sha256": payload_hash, "payload": payload}
    event_hash = sha256_hex(DOMAIN + canonical_json(body))
    signature = key.sign(SIG_DOMAIN + bytes.fromhex(event_hash)).hex()
    return {**body, "event_hash": event_hash, "signature": signature}


def verify_signed_event(event: Mapping, key: Ed25519PublicKey, *,
                        expected_previous_event_hash: str | None = None) -> dict:
    """Recompute payload and event hashes before checking the signature."""
    try:
        expected = {"schema_version", "key_id", "previous_event_hash",
                    "payload_sha256", "payload", "event_hash", "signature"}
        if not isinstance(event, Mapping) or set(event) != expected:
            return {"valid": False, "reason": "invalid_fields"}
        if event["schema_version"] != SCHEMA:
            return {"valid": False, "reason": "unsupported_schema"}
        if event["previous_event_hash"] != expected_previous_event_hash:
            return {"valid": False, "reason": "chain_link_mismatch"}
        payload = event["payload"]
        if not isinstance(payload, Mapping):
            return {"valid": False, "reason": "payload_not_object"}
        digest = sha256_hex(canonical_json(dict(payload)))
        if digest != event["payload_sha256"]:
            return {"valid": False, "reason": "payload_digest_mismatch"}
        body = {k: event[k] for k in (
            "schema_version", "key_id", "previous_event_hash", "payload_sha256", "payload"
        )}
        actual_hash = sha256_hex(DOMAIN + canonical_json(body))
        if actual_hash != event["event_hash"]:
            return {"valid": False, "reason": "event_hash_mismatch"}
        key.verify(bytes.fromhex(event["signature"]), SIG_DOMAIN + bytes.fromhex(actual_hash))
        return {"valid": True, "reason": "verified", "event_hash": actual_hash}
    except InvalidSignature:
        return {"valid": False, "reason": "signature_invalid"}
    except (KeyError, TypeError, ValueError):
        return {"valid": False, "reason": "malformed_event"}
