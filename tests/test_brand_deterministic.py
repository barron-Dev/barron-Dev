from cyclothone.brand.deterministic import (
    compare_domains,
    damerau_levenshtein,
    normalize_domain,
    sha256_hex,
)


def test_homoglyph_skeleton_is_stable():
    assert normalize_domain("раypal.com") == normalize_domain("paypal.com")


def test_url_and_host_normalize_identically():
    assert normalize_domain("https://Example.com/login") == "example.com"


def test_damerau_counts_adjacent_transposition_as_one():
    assert damerau_levenshtein("acme.com", "acme.com") == 0
    assert damerau_levenshtein("acme.com", "acme.coｍ") == 0
    assert damerau_levenshtein("ab.com", "ba.com") == 1


def test_domain_comparison_never_promotes_to_verified():
    result = compare_domains("paypal.com", "раypal.com")
    assert result["exact_skeleton_match"] is True
    assert result["verification_state"] == "candidate"


def test_sha256_is_canonical():
    assert sha256_hex(b"cyclothone") == "0c488cf262c4d8f38130646384fb0a77e4710fd984cdd5268e19c91f28a116cd
