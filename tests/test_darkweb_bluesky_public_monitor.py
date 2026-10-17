from unittest.mock import patch

import pytest

from cyclothone.darkweb.pullers import BlueskyPublicMonitor


class _Response:
    def __init__(self, payload=None, status_error=False):
        self._payload = payload or {"posts": []}
        self._status_error = status_error

    def raise_for_status(self):
        if self._status_error:
            raise RuntimeError("HTTP error")

    def json(self):
        return self._payload


class _Client:
    response = None
    last_request = None

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        type(self).last_request = (url, kwargs)
        return type(self).response


@pytest.mark.asyncio
async def test_bluesky_public_monitor_reports_exact_public_identifier_without_storing_post_text():
    _Client.response = _Response({
        "posts": [
            {
                "uri": "at://did:plc:example/app.bsky.feed.post/abc123",
                "author": {"handle": "public.example"},
                "record": {"text": "We saw security@example.org in this public post."},
            },
            {
                "uri": "at://did:plc:other/app.bsky.feed.post/def456",
                "author": {"handle": "other.example"},
                "record": {"text": "A different unrelated public post."},
            },
        ]
    })
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", _Client):
        findings = await BlueskyPublicMonitor().pull("email", "Security@Example.org")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_id == "bluesky_public"
    assert finding.kind == "email"
    assert finding.matched_value == "security@example.org"
    assert finding.source_url == "https://bsky.app/profile/public.example/post/abc123"
    assert "security@example.org" not in str(finding.metadata)
    assert "observed_text_sha256" in finding.metadata
    url, kwargs = _Client.last_request
    assert url.endswith("/xrpc/app.bsky.feed.searchPosts")
    assert kwargs["params"]["q"] == "security@example.org"
    assert kwargs["params"]["limit"] == 25


@pytest.mark.asyncio
async def test_bluesky_public_monitor_accepts_zero_match_success_as_empty_result():
    _Client.response = _Response({"posts": []})
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", _Client):
        findings = await BlueskyPublicMonitor().pull("domain", "example.org")
    assert findings == []


@pytest.mark.asyncio
async def test_bluesky_public_monitor_rejects_unsupported_target_without_request():
    _Client.last_request = None
    with patch("cyclothone.darkweb.pullers.httpx.AsyncClient", _Client):
        with pytest.raises(RuntimeError, match="unsupported Bluesky target type"):
            await BlueskyPublicMonitor().pull("other", "example.org")
    assert _Client.last_request is None
