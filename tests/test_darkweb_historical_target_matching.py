from cyclothone.darkweb.request_worker import _finding_matches_target


def test_domain_request_includes_historical_exact_email_at_domain():
    row = {"kind": "email", "matched_value": "security@example.org"}
    assert _finding_matches_target(row, "domain", "example.org")


def test_domain_request_does_not_include_email_at_lookalike_or_subdomain():
    assert not _finding_matches_target(
        {"kind": "email", "matched_value": "security@notexample.org"},
        "domain", "example.org",
    )
    assert not _finding_matches_target(
        {"kind": "email", "matched_value": "security@sub.example.org"},
        "domain", "example.org",
    )


def test_historical_exact_match_is_case_insensitive_for_all_targets():
    assert _finding_matches_target(
        {"kind": "domain", "matched_value": "EXAMPLE.ORG"},
        "domain", "example.org",
    )


def test_provider_finding_objects_keep_existing_exact_match_behavior():
    class Finding:
        kind = "domain"
        matched_value = "example.org"

    assert _finding_matches_target(Finding(), "domain", "example.org")
