from cyclothone.security_state.materializer import _attempted, _sources


def test_structured_source_outcomes_are_preserved():
    outcomes = [
        {"name": "ransomwatch", "status": "succeeded", "attempted": True, "records_returned": 12},
        {"name": "hibp", "status": "unavailable", "attempted": False, "error_code": "credential_missing"},
    ]
    assert _sources({"sources": outcomes}) == outcomes
    assert _attempted(outcomes[0]) is True
    assert _attempted(outcomes[1]) is False


def test_source_results_take_precedence_over_legacy_source_names():
    outcomes = [{"name": "github_code", "status": "failed", "attempted": True}]
    assert _sources({"source_results": outcomes, "sources": ["github_code"]}) == outcomes


def test_legacy_source_names_remain_readable():
    assert _sources({"sources": ["ransomwatch", "hibp"]}) == [
        {"name": "ransomwatch", "status": "succeeded", "attempted": True},
        {"name": "hibp", "status": "succeeded", "attempted": True},
    ]
