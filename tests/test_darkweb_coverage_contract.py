from cyclothone.darkweb.request_worker import _coverage_state


def test_coverage_is_none_when_no_provider_was_checked():
    assert _coverage_state([
        {"source": "hibp", "state": "unavailable", "reason": "missing_key"},
        {"source": "github_code", "state": "failed", "reason": "timeout"},
    ]) == "none"


def test_coverage_is_partial_when_any_provider_is_unavailable_or_failed():
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "unavailable", "reason": "missing_key"},
    ]) == "partial"


def test_coverage_only_says_all_configured_sources_checked_when_every_check_succeeded():
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "checked"},
    ]) == "all_configured_sources_checked"
