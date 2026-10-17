from cyclothone.darkweb.request_worker import _coverage_state


def test_archived_and_planned_sources_do_not_inflate_live_coverage_denominator():
    sources = [
        {"source": "native_onion", "availability": "implemented", "state": "checked"},
        {"source": "telegram_public", "availability": "implemented", "state": "checked"},
        {"source": "ransomwatch", "availability": "historical_only", "state": "unavailable"},
        {"source": "github_code", "availability": "planned", "state": "unavailable"},
    ]
    assert _coverage_state(sources) == "all_configured_live_sources_checked"


def test_unreachable_implemented_source_keeps_coverage_partial():
    sources = [
        {"source": "native_onion", "availability": "implemented", "state": "failed"},
        {"source": "telegram_public", "availability": "implemented", "state": "checked"},
        {"source": "github_code", "availability": "planned", "state": "unavailable"},
    ]
    assert _coverage_state(sources) == "partial"


def test_no_successful_live_source_means_no_coverage():
    sources = [
        {"source": "native_onion", "availability": "implemented", "state": "unavailable"},
        {"source": "ransomwatch", "availability": "historical_only", "state": "checked"},
        {"source": "github_code", "availability": "planned", "state": "checked"},
    ]
    assert _coverage_state(sources) == "none"
