from cyclothone.darkweb.honeytokens import create_honeytoken, detect_honeytoken


def test_honeytoken_is_high_entropy_and_only_digest_is_in_record():
    record, raw = create_honeytoken("customer mailbox canary", token_id="canary-1")
    assert raw.startswith("cyc-canary-")
    assert raw not in repr(record)
    assert record.token_sha256
    assert len(record.token_sha256) == 64


def test_detector_matches_exact_token_without_returning_secret():
    record, raw = create_honeytoken("approved test", token_id="canary-2")
    assert detect_honeytoken(f"leaked text {raw} end", {record.token_id: record.token_sha256}) == ["canary-2"]
    assert detect_honeytoken(f"leaked text {raw}x end", {record.token_id: record.token_sha256}) == []


def test_detector_fails_closed_for_invalid_registry_values():
    assert detect_honeytoken("cyc-canary-anything", {}) == []
    assert detect_honeytoken("cyc-canary-anything", {"bad": "not-a-digest"}) == []


def test_label_validation():
    import pytest

    with pytest.raises(ValueError):
        create_honeytoken(" ", token_id="canary-3")
    with pytest.raises(ValueError):
        create_honeytoken("ok", token_id="")
