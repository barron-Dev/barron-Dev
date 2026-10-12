from __future__ import annotations

from unittest.mock import patch

import pytest

from cyclothone.darkweb.bluesky import BlueskyPublicMonitor


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _Client:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, *, params, headers):
        self.calls += 1
        if self.calls == 1:
            return _Response({
                "feed": [
                    {"post": {
                        "uri": "at://did:plc:alice/app.bsky.feed.post/abc123",
                        "record": {"text": "We found example.com in a public disclosure."},
                        "author": {"handle": "alice.bsky.social"},
                        "indexedAt": "2026-10-12T09:00:00Z",
                    }},
                    {"post": {
                        "uri": "at://did:plc:bad/app.bsky.feed.post/evil",
                        "record": {"text": "example.com.evil is not the monitored domain."},
                        "author": {"handle": "bad.bsky.social"},
                    }},
                ],
                "cursor": "next-page",
            })
        return _Response({
            "feed": [
                {"post": {
                    "uri": "at://did:plc:alice/app.bsky.feed.post/abc123",
                    "record": {"text": "duplicate exact mention example.com"},
                    "author": {"handle": "alice.bsky.social"},
                }},
                {"post": {
                    "uri": "at://did:plc:bob/app.bsky.feed.post/xyz789",
                    "record": {"text": "A general public post without the monitored domain."},
                    "author": {"handle": "bob.bsky.social"},
                }},
            ],
        })


@pytest.mark.asyncio
async def test_bluesky_public_search_keeps_exact_domain_matches_and_deduplicates_posts():
    monitor = BlueskyPublicMonitor()
    fake = _Client()
    with patch("cyclothone.darkweb.bluesky.httpx.AsyncClient", return_value=fake):
        findings = await monitor.pull_target("Example.com", "domain")

    assert len(findings) == 1
    assert findings[0].source_id == "bluesky_public"
    assert findings[0].kind == "domain"
    assert findings[0].matched_value == "example.com"
    assert findings[0].source_url == "https://bsky.app/profile/alice.bsky.social/post/abc123"
    assert findings[0].metadata["post_uri"].endswith("/abc123")
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_bluesky_public_search_requires_exact_email_mention():
    monitor = BlueskyPublicMonitor()
    fake = _Client()
    fake.calls = 1
    fake.get = _email_page
    with patch("cyclothone.darkweb.bluesky.httpx.AsyncClient", return_value=fake):
        findings = await monitor.pull_target("security@example.com", "email")

    assert [finding.matched_value for finding in findings] == ["security@example.com"]


async def _email_page(url, *, params, headers):
    return _Response({
        "feed": [
            {"post": {
                "uri": "at://did:plc:bob/app.bsky.feed.post/email1",
                "record": {"text": "security@example.com was referenced."},
                "author": {"handle": "bob.bsky.social"},
            }},
            {"post": {
                "uri": "at://did:plc:bad/app.bsky.feed.post/email2",
                "record": {"text": "security@example.com.attacker.test is not the address."},
                "author": {"handle": "bad.bsky.social"},
            }},
        ],
    })


def test_bluesky_exact_mention_rejects_hostname_suffixes():
    assert BlueskyPublicMonitor._exact_mention("example.com", "example.com", "domain")
    assert not BlueskyPublicMonitor._exact_mention("example.com.evil", "example.com", "domain")
