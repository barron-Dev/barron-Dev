from sentinel.web.deep import _safe_metadata, _hash_identifier


def test_identifier_hash_is_stable_and_case_normalized():
    assert _hash_identifier(" CEO@Example.COM ") == _hash_identifier("ceo@example.com")


def test_secret_fields_are_never_returned_in_metadata():
    result = _safe_metadata({"email": "a@example.com", "password": "secret", "token": "bearer", "database": "db1"})
    assert result == {"email": "a@example.com", "database": "db1"}
