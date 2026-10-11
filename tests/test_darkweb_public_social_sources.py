from cyclothone.darkweb.pullers import TelegramPublicMonitor


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
