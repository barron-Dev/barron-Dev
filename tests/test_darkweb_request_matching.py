from cyclothone.darkweb.pullers import Finding
from cyclothone.darkweb.request_worker import _finding_matches_target


def _finding(kind: str, matched_value: str) -> Finding:
    return Finding(
        source_id="hibp",
        kind=kind,
        matched_value=matched_value,
        context="public breach indicator",
        severity="high",
        source_url=None,
        metadata={},
    )


def test_hibp_breached_email_matches_exact_monitored_domain():
    finding = _finding("email", "security@owned-example.com")

    assert _finding_matches_target(finding, "domain", "owned-example.com")


def test_hibp_breached_email_does_not_match_a_similar_domain():
    finding = _finding("email", "security@owned-example.com.attacker.test")

    assert not _finding_matches_target(finding, "domain", "owned-example.com")


def test_exact_domain_findings_still_match_without_fuzzy_matching():
    assert _finding_matches_target(
        _finding("domain", "owned-example.com"),
        "domain",
        "owned-example.com",
    )
    assert not _finding_matches_target(
        _finding("domain", "owned-example.com.attacker.test"),
        "domain",
        "owned-example.com",
    )
