from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import HIBPPuller


class _Response:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return [{"Name": "ExampleBreach", "Title": "Example Breach"}]


class _Client:
    def __init__(self, *args, **kwargs):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response()


@pytest.mark.asyncio
async def test_hibp_account_lookup_returns_email_finding_without_breach_payload():
    client = _Client()
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=client):
        findings = await HIBPPuller("test-api-key").pull_account("Security@Owned-Example.com")

    assert len(findings) == 1
    assert findings[0].kind == "email"
    assert findings[0].matched_value == "security@owned-example.com"
    assert findings[0].metadata == {"breach": "ExampleBreach"}
    assert len(client.calls) == 1
    url, kwargs = client.calls[0]
    assert url.endswith("/breachedaccount/security%40owned-example.com")
    assert kwargs["params"] == {"truncateResponse": "false", "includeUnverified": "false"}
    assert kwargs["headers"]["hibp-api-key"] == "test-api-key"


@pytest.mark.asyncio
async def test_hibp_account_lookup_rejects_malformed_email_without_network():
    client = _Client()
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", return_value=client):
        findings = await HIBPPuller("test-api-key").pull_account("not-an-email")

    assert findings == []
    assert client.calls == []
