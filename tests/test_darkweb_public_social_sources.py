from cyclothone.darkweb.pullers import TelegramPublicMonitor, YouTubePublicMonitor


def test_telegram_domain_match_is_exact_and_source_attributed() -> None:
    monitor = TelegramPublicMonitor(
        ["public_channel"],
        target_type="domain",
        target="example.com",
    )

    findings = monitor._target_finding(
        '<div>Victim: example.com</div><div>Unrelated: notexample.com</div>',
        "public_channel",
    )

    assert len(findings) == 1
    assert findings[0].source_id == "telegram_public"
    assert findings[0].kind == "domain"
    assert findings[0].matched_value == "example.com"
    assert findings[0].source_url == "https://t.me/s/public_channel"
    assert findings[0].metadata["match_type"] == "exact_domain_mention"


def test_telegram_non_matching_domain_does_not_create_finding() -> None:
    monitor = TelegramPublicMonitor(
        ["public_channel"],
        target_type="domain",
        target="example.com",
    )

    assert monitor._target_finding(
        '<div>example.com.attacker.invalid</div>',
        "public_channel",
    ) == []


def test_telegram_brand_match_is_phrase_exact() -> None:
    monitor = TelegramPublicMonitor(
        ["public_channel"],
        target_type="brand",
        target="Chara Enterprise",
    )

    findings = monitor._target_finding(
        "<div>Chara Enterprise reported in public post.</div>",
        "public_channel",
    )

    assert len(findings) == 1
    assert findings[0].kind == "company_name"
    assert findings[0].matched_value == "chara enterprise"
    assert findings[0].metadata["match_type"] == "exact_brand_mention"


def test_telegram_username_match_requires_at_handle() -> None:
    monitor = TelegramPublicMonitor(
        ["public_channel"],
        target_type="username",
        target="sample_user",
    )

    assert monitor._target_finding("<div>sample_user</div>", "public_channel") == []
    findings = monitor._target_finding("<div>@sample_user mentioned</div>", "public_channel")
    assert len(findings) == 1
    assert findings[0].kind == "username"



def test_youtube_matches_exact_domain_and_records_public_video_url(monkeypatch) -> None:
    import asyncio

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "items": [
                    {
                        "id": {"videoId": "video123"},
                        "snippet": {
                            "title": "Example update: example.com",
                            "description": "Public mention",
                            "publishedAt": "2026-10-15T12:00:00Z",
                            "channelId": "channel123",
                        },
                    },
                    {
                        "id": {"videoId": "video456"},
                        "snippet": {
                            "title": "Unrelated site mention",
                            "description": "A mention of notexample.com should not match",
                            "publishedAt": "2026-10-15T12:00:00Z",
                            "channelId": "channel456",
                        },
                    },
                ]
            }

    class Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr("cyclothone.darkweb.pullers.httpx.AsyncClient", Client)
    findings = asyncio.run(YouTubePublicMonitor("test-key").pull_domains(["example.com"]))

    assert len(findings) == 1
    assert findings[0].source_id == "youtube_public"
    assert findings[0].matched_value == "example.com"
    assert findings[0].source_url == "https://www.youtube.com/watch?v=video123"
    assert findings[0].metadata["published"] == "2026-10-15T12:00:00Z"
    assert "Example update" not in str(findings[0].metadata)


def test_youtube_missing_api_key_is_unavailable_not_a_clean_result() -> None:
    import asyncio
    import pytest

    with pytest.raises(RuntimeError, match="youtube_api_key_required"):
        asyncio.run(YouTubePublicMonitor("").pull_domains(["example.com"]))
