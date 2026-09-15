from sentinel.developer.crypto import hash_secret, verify_pkce


def test_hash_is_deterministic_and_not_plaintext() -> None:
    value = "super-secret"
    digest = hash_secret(value)
    assert digest != value
    assert digest == hash_secret(value)


def test_pkce_s256() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert verify_pkce(verifier, challenge, "S256")
    assert not verify_pkce("wrong", challenge, "S256")


def test_pkce_plain() -> None:
    assert verify_pkce("abc", "abc", "plain")
    assert not verify_pkce("abc", "abd", "plain")
