from __future__ import annotations

import hashlib

from cyclothone.provenance.c2pa_verify import (
    STATES, ZERO_HASH, build_receipt_hash, canonical_json, classify_validation,
)


def test_five_states_are_closed_set():
    assert STATES == {"VALID", "INVALID", "UNTRUSTED", "MISSING_PROVENANCE", "INDETERMINATE"}


def test_cai_trusted_state_is_valid_only_with_configured_anchors():
    assert classify_validation("Trusted", {}, True) == "VALID"
    assert classify_validation("Trusted", {}, False) == "UNTRUSTED"


def test_cai_valid_state_is_valid_but_untrusted():
    assert classify_validation("Valid", {}, True) == "UNTRUSTED"
    assert classify_validation("Valid", {}, False) == "UNTRUSTED"


def test_integrity_failure_is_invalid():
    results = {"validation_status": [{"code": "assertion.dataHash.mismatch"}]}
    assert classify_validation("Invalid", results, True) == "INVALID"


def test_unknown_validation_failure_abstains():
    assert classify_validation("Invalid", {"validation_status": [{"code": "unmapped.error"}]}, True) == "INDETERMINATE"


def test_trust_failure_is_untrusted():
    results = {"validation_status": [{"code": "signingCredential.untrusted"}]}
    assert classify_validation("Invalid", results, True) == "UNTRUSTED"


def test_receipt_hash_is_canonical_and_deterministic():
    payload = {"b": 2, "a": 1}
    assert build_receipt_hash(payload) == hashlib.sha256(canonical_json(payload)).hexdigest()
    assert build_receipt_hash(payload) == build_receipt_hash({"a": 1, "b": 2})
    assert len(ZERO_HASH) == 64
