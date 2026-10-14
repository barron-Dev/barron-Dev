from cyclothone.darkweb.pullers import Finding
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from cyclothone.darkweb.request_worker import (
    _finding_matches_target,
    _historical_finding_matches_target,
    _load_historical_matches,
)


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



def test_historical_domain_correlation_matches_exact_domain_and_exact_email_domain():
    assert _historical_finding_matches_target(
        {"kind": "domain", "matched_value": "owned-example.com"},
        "domain",
        "owned-example.com",
    )
    assert _historical_finding_matches_target(
        {"kind": "email", "matched_value": "security@owned-example.com"},
        "domain",
        "owned-example.com",
    )


def test_historical_domain_correlation_rejects_lookalikes():
    assert not _historical_finding_matches_target(
        {"kind": "domain", "matched_value": "owned-example.com.attacker.test"},
        "domain",
        "owned-example.com",
    )
    assert not _historical_finding_matches_target(
        {"kind": "email", "matched_value": "security@owned-example.com.attacker.test"},
        "domain",
        "owned-example.com",
    )


@pytest.mark.asyncio
async def test_historical_correlation_pages_past_default_postgrest_limit():
    tenant_id = "bc10ea43-9aa6-4c5f-a792-c10dbcc19b28"
    rows = [
        {
            "id": index + 1,
            "source_id": "github_code",
            "content_hash": f"hash-{index}",
            "kind": "domain",
            "matched_value": f"unrelated-{index}.example",
            "tenant_id": tenant_id,
            "watchlist_id": None,
        }
        for index in range(501)
    ]
    rows[-1]["matched_value"] = "owned-example.com"

    class Query:
        def __init__(self):
            self.start = 0
            self.end = 0

        def select(self, _columns):
            return self

        def or_(self, _expression):
            return self

        def order(self, _column):
            return self

        def range(self, start, end):
            self.start, self.end = start, end
            return self

        async def execute(self):
            return SimpleNamespace(data=rows[self.start:self.end + 1])

    class Client:
        def table(self, _table):
            return Query()

    async def retry(operation, attempts=2):
        return await operation()

    with patch(
        "cyclothone.darkweb.request_worker.supabase._ensure",
        new=AsyncMock(return_value=Client()),
    ), patch(
        "cyclothone.darkweb.request_worker.supabase._retry",
        side_effect=retry,
    ):
        matches, scanned = await _load_historical_matches(
            tenant_id, "domain", "owned-example.com", page_size=500
        )

    assert scanned == 501
    assert len(matches) == 1
    assert matches[0]["id"] == 501
