from datetime import UTC, datetime

from cyclothone.darkweb.source_status import source_health


NOW = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)


def row(**updates):
    base = {
        "id": "ransomwatch",
        "name": "Ransomwatch",
        "kind": "ransomware_leak",
        "enabled": True,
        "last_pull_at": "2026-10-10T07:50:00+00:00",
        "last_status": "ok",
        "poll_interval_seconds": 900,
    }
    return {**base, **updates}


def test_disabled_source_is_not_reported_healthy():
    assert source_health(row(enabled=False), now=NOW)["health"] == "disabled"


def test_credentialed_source_without_key_is_blocked():
    result = source_health(row(id="hibp"), now=NOW, environ={})
    assert result["health"] == "blocked_missing_credentials"
    assert result["configuration_ready"] is False


def test_missing_first_pull_is_unverified_not_healthy():
    result = source_health(row(last_pull_at=None, last_status=None), now=NOW, environ={})
    assert result["health"] == "not_yet_verified"


def test_failed_and_degraded_runs_are_preserved():
    assert source_health(row(last_status="failed"), now=NOW, environ={})["health"] == "failed"
    assert source_health(row(last_status="degraded"), now=NOW, environ={})["health"] == "degraded"


def test_old_successful_run_is_stale():
    result = source_health(
        row(last_pull_at="2026-10-10T05:00:00+00:00"),
        now=NOW,
        environ={},
    )
    assert result["health"] == "stale"


def test_recent_successful_public_source_is_healthy():
    result = source_health(row(), now=NOW, environ={})
    assert result["health"] == "ok"
    assert result["configuration_ready"] is True


def test_health_never_returns_environment_secret_values():
    result = source_health(
        row(id="hibp"),
        now=NOW,
        environ={"CYCLOTHONE_HIBP_KEY": "never-return-this-secret"},
    )
    assert "never-return-this-secret" not in repr(result)
