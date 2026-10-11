from cyclothone.darkweb.pullers import TelegramPublicMonitor


def test_telegram_domain_target_requires_hostname_boundaries() -> None:
    monitor = TelegramPublicMonitor(["public_channel"], target_type="domain", target="example.com")

    exact = monitor._target_finding("<div>example.com was mentioned</div>", "public_channel")
    unrelated = monitor._target_finding("<div>notexample.com.evil was mentioned</div>", "public_channel")

    assert len(exact) == 1
    assert exact[0].kind == "domain"
    assert exact[0].matched_value == "example.com"
    assert exact[0].metadata["match_type"] == "exact_domain_mention"
    assert unrelated == []


def test_telegram_brand_target_matches_exact_phrase_without_retaining_post_text() -> None:
    monitor = TelegramPublicMonitor(["public_channel"], target_type="brand", target="Chara Enterprise")

    findings = monitor._target_finding("<div>CH​ARA ENTERPRISE was mentioned</div>".replace("\u200b", ""), "public_channel")

    assert len(findings) == 1
    assert findings[0].kind == "company_name"
    assert findings[0].matched_value == "chara enterprise"
    assert findings[0].source_url == "https://t.me/s/public_channel"
    assert findings[0].context is not None
    assert "post content is not retained" in findings[0].context.lower()


def test_telegram_email_target_matches_only_the_requested_email() -> None:
    monitor = TelegramPublicMonitor(["public_channel"], target_type="email", target="security@example.com")

    findings = monitor._target_finding(
        "<div>security@example.com and other@example.com</div>",
        "public_channel",
    )

    assert len(findings) == 1
    assert findings[0].kind == "email"
    assert findings[0].matched_value == "security@example.com"
