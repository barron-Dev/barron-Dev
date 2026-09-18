from cyclothone.darkweb.matcher import max_severity
from cyclothone.darkweb.pullers import normalize, value_hash


def test_normalization_is_stable():
    assert normalize(" CEO@Example.COM ") == "ceo@example.com"
    assert value_hash(" CEO@Example.COM ") == value_hash("ceo@example.com")


def test_severity_escalates_only_upward():
    assert max_severity("medium", "critical") == "critical"
    assert max_severity("critical", "medium") == "critical"
    assert max_severity("high", "medium") == "high"


def test_unknown_severity_fails_closed_to_known_baseline():
    assert max_severity("unknown", "medium") == "medium"
    assert max_severity("critical", "unknown") == "critical"


def test_hashed_watch_values_are_not_case_sensitive():
    assert value_hash("Example.org") == value_hash("example.ORG")
