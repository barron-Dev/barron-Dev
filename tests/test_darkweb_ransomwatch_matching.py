from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import RansomwatchPuller, _domain_from_victim_title


def test_ransomwatch_domain_is_extracted_only_from_exact_victim_title():
    assert _domain_from_victim_title("owned-example.com") == "owned-example.com"
    assert _domain_from_victim_title("https://owned-example.com/") == "owned-example.com"
    assert _domain_from_victim_title("Victim Corporation") is None
    assert _domain_from_victim_title("owned-example.com attacker.test") is None


class _Response:
    def raise_for_status(self):
        return None

    def json(self):
        return [
            {
                "post_title": "Victim Corporation",
                "post_url": "https://leak-group.example/victim-post",
                "group_name": "example-group",
                "discovered": "2026-10-10",
            },
            {
                "post_title": "owned-example.com",
                "post_url": "https://leak-group.example/domain-post",
                "group_name": "example-group",
                "discovered": "2026-10-10",
            },
        ]


class _Client:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url: str, **kwargs):
        assert url == RansomwatchPuller.FEED
        return _Response()


@pytest.mark.asyncio
async def test_ransomwatch_does_not_claim_leak_site_host_as_victim_domain():
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=_Client()):
        findings = await RansomwatchPuller().pull()

    domains = [finding.matched_value for finding in findings if finding.kind == "domain"]
    assert domains == ["owned-example.com"]
    assert all(finding.matched_value != "leak-group.example" for finding in findings)
