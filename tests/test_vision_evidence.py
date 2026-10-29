import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyclothone.vision.evidence import canonical_json, create_signed_event, hash_media_bytes, verify_signed_event


def test_canonical_json_is_stable_and_rejects_nan():
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    with pytest.raises(ValueError):
        canonical_json({"score": float("nan")})


def test_media_hash_uses_exact_bytes():
    assert hash_media_bytes(b"clip") != hash_media_bytes(b"clip ")


def test_signed_event_verifies_and_detects_payload_tamper():
    key = Ed25519PrivateKey.generate()
    event = create_signed_event({"frame_sha256": "a" * 64}, key, key_id="edge-1")
    assert verify_signed_event(event, key.public_key())["valid"]
    changed = copy.deepcopy(event)
    changed["payload"]["frame_sha256"] = "b" * 64
    assert verify_signed_event(changed, key.public_key())["reason"] == "payload_digest_mismatch"


def test_chain_link_is_enforced():
    key = Ed25519PrivateKey.generate()
    first = create_signed_event({"sequence": 1}, key, key_id="edge-1")
    second = create_signed_event({"sequence": 2}, key, key_id="edge-1",
                                 previous_event_hash=first["event_hash"])
    assert verify_signed_event(second, key.public_key(),
                               expected_previous_event_hash=first["event_hash"])["valid"]
    assert verify_signed_event(second, key.public_key(),
                               expected_previous_event_hash="f" * 64)["reason"] == "chain_link_mismatch"


def test_signature_tampering_fails():
    key = Ed25519PrivateKey.generate()
    event = create_signed_event({"event_type": "fall"}, key, key_id="edge-1")
    event["signature"] = "00" * 64
    assert verify_signed_event(event, key.public_key())["reason"] == "signature_invalid"


def test_extra_fields_are_rejected():
    key = Ed25519PrivateKey.generate()
    event = create_signed_event({"event_type": "fall"}, key, key_id="edge-1")
    event["verified"] = True
    assert verify_signed_event(event, key.public_key())["reason"] == "invalid_fields"
