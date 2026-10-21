from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.silence import evaluate_silence, silence_pvalue


def test_poisson_zero_probability_is_monotonic_with_gap():
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    last = now - timedelta(hours=3)
    short = silence_pvalue(last, now, 0.5)
    long = silence_pvalue(last - timedelta(hours=5), now, 0.5)
    assert 0 <= short <= 1
    assert long < short


def test_negative_binomial_size_parameter_is_used_as_size_not_variance_ratio():
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    last = now - timedelta(hours=8)
    assert silence_pvalue(last, now, 0.5, 0.5) > silence_pvalue(last, now, 0.5)


def test_unhealthy_monitoring_never_reports_source_silence():
    result = evaluate_silence(
        [], now=datetime(2026, 10, 21, tzinfo=UTC),
        last_document_at=None, monitoring_healthy=False,
    )
    assert result["state"] == "monitoring_unavailable"
    assert result["p_value"] is None


def test_cold_start_does_not_emit_silence_candidate():
    now = datetime(2026, 10, 21, tzinfo=UTC)
    result = evaluate_silence(
        [], now=now, last_document_at=now - timedelta(days=2),
        monitoring_healthy=True,
    )
    assert result["state"] == "insufficient_baseline"


def test_zero_baseline_rate_is_not_called_silence():
    now = datetime(2026, 10, 21, tzinfo=UTC)
    start = now - timedelta(days=56)
    buckets = []
    for week in range(8):
        for slot in range(168):
            stamp = start + timedelta(days=week * 7, hours=slot)
            buckets.append({
                "bucket_hour": stamp.isoformat(),
                "documents_new_sum": 0,
                "complete_poll_count": 4,
                "failed_poll_count": 0,
            })
    result = evaluate_silence(
        buckets, now=now, last_document_at=now - timedelta(days=2),
        monitoring_healthy=True,
    )
    assert result["state"] == "no_expected_activity"
