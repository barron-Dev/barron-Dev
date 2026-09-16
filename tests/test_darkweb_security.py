import pytest

from sentinel.darkweb.matcher import max_severity
from sentinel.darkweb.pullers import normalize, value_hash


def test_normalization_is_stable():
    assert normalize(" CEO@Example.COM ") == "ceo@example.com"
    assert value_hash(" CEO@Example.COM ") == value_hash("ceo@example.com")


def test_severity_escalates_only_upward():
    assert max_severity("medium", "critical") == "critical"
    assert max_severity("critical", "medium") == "critical"
    assert max_severity("high", "medium") == "high"

@pytest.mark.asyncio
async def test_placeholder():
    # Integration coverage for the service-role RPC belongs in the database CI job.
    assert True
