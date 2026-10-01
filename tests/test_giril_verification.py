import pytest
from src.cyclothone.giril.verification import build_target, normalize_email, normalize_phone, normalize_lei, summarize_gleif


def test_email_and_phone_normalization():
    assert normalize_email(" User@Example.COM ") == "user@example.com"
    assert normalize_phone("+971 (50) 123-4567") == "+971501234567"


def test_target_hash_is_stable_and_not_plaintext():
    target = build_target("LEI", "529900T8BM49AURSDO55")
    assert len(target.target_hash) == 64
    assert target.value not in target.target_hash


def test_invalid_targets_fail_closed():
    with pytest.raises(ValueError):
        normalize_phone("abc")
    with pytest.raises(ValueError):
        normalize_lei("123")


def test_gleif_summary_minimizes_response():
    payload = {"data": [{"attributes": {"lei": "X", "entityStatus": "ACTIVE", "entity": {"legalName": {"name": "Example"}, "legalAddress": {"country": "AE"}}, "registration": {"status": "ISSUED"}}}]}
    result = summarize_gleif(payload)
    assert result["record_count"] == 1
    assert result["records"][0]["legal_name"] == "Example"
    assert "attributes" not in result["records"][0]
