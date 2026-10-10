from __future__ import annotations

import hashlib

import pytest

from cyclothone.identity_graph import (
    canonicalize,
    identifier_hash,
    score_identity_link,
    validate_content_hash,
)


def test_email_canonicalization_is_case_insensitive_for_search():
    assert canonicalize("email", " Alice@Example.COM ") == "alice@example.com"


def test_domain_and_profile_url_canonicalization():
    assert canonicalize("domain", "HTTPS://Example.COM/path") == "example.com"
    assert canonicalize("social_account", "https://Example.com/@alice/?ref=feed") == "https://example.com/@alice"


def test_ip_address_uses_compressed_canonical_form():
    assert canonicalize("ip_address", "2001:0db8:0:0:0:0:0:1") == "2001:db8::1"


@pytest.mark.parametrize(
    ("kind", "value"),
    [("email", "not-an-email"), ("domain", "localhost"), ("ip_address", "999.1.1.1"), ("phone", "123")],
)
def test_invalid_identifiers_fail_closed(kind, value):
    with pytest.raises(ValueError):
        canonicalize(kind, value)


def test_identifier_hash_is_stable_sha256():
    value = "alice@example.com"
    assert identifier_hash(value) == hashlib.sha256(value.encode()).hexdigest()


def test_weak_signals_never_cross_candidate_review_threshold():
    result = score_identity_link(["exact_username", "same_display_name", "shared_email_domain"])
    assert result["confidence"] <= 0.49
    assert result["auto_confirmed"] is False


def test_strong_signal_is_explainable_but_not_auto_confirmed():
    result = score_identity_link(["same_verified_public_profile_url"])
    assert result["confidence_percent"] == 95.0
    assert result["signals"] == ["same_verified_public_profile_url"]
    assert result["auto_confirmed"] is False


def test_unknown_signal_is_rejected():
    with pytest.raises(ValueError, match="unsupported_identity_signals"):
        score_identity_link(["facial_similarity"])


def test_content_hash_validation():
    digest = "A" * 64
    assert validate_content_hash(digest) == digest.lower()
    with pytest.raises(ValueError):
        validate_content_hash("not-a-digest")
