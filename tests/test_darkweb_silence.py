from datetime import UTC, datetime, timedelta

from cyclothone.darkweb.silence import derive_cursor_delta, evaluate_silence, silence_pvalue


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



def test_first_cursor_is_initialization_not_a_zero_count():
    result = derive_cursor_delta([10, 11, 12], None)
    assert result == {
        "cursor_value": 12,
        "documents_new": None,
        "count_complete": False,
        "error_code": "cursor_initialized",
    }


def test_visible_cursor_with_no_new_posts_is_a_complete_zero():
    result = derive_cursor_delta([10, 11, 12], 12)
    assert result["documents_new"] == 0
    assert result["count_complete"] is True
    assert result["error_code"] is None


def test_missing_previous_cursor_is_unknown_not_silence():
    result = derive_cursor_delta([30, 31, 32], 12)
    assert result["documents_new"] is None
    assert result["count_complete"] is False
    assert result["error_code"] == "cursor_not_visible"



def _eight_week_hourly_buckets(now, documents_per_hour=1):
    start = now - timedelta(days=56)
    buckets = []
    for week in range(8):
        for slot in range(168):
            stamp = start + timedelta(days=week * 7, hours=slot)
            buckets.append({
                "bucket_hour": stamp.isoformat(),
                "documents_new_sum": documents_per_hour,
                "complete_poll_count": 4,
                "failed_poll_count": 0,
            })
    return buckets


def test_healthy_eight_week_baseline_can_only_create_shadow_candidate():
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    result = evaluate_silence(
        _eight_week_hourly_buckets(now),
        now=now,
        last_document_at=now - timedelta(hours=5),
        monitoring_healthy=True,
    )
    assert result["state"] == "silence_candidate"
    assert result["shadow_only"] is True
    assert result["p_value"] <= 0.01


def test_failed_collection_hour_blocks_silence_candidate():
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    buckets = _eight_week_hourly_buckets(now)
    failed_hour = (now - timedelta(hours=2)).isoformat()
    for bucket in buckets:
        if bucket["bucket_hour"] == failed_hour:
            bucket["failed_poll_count"] = 1
            break
    result = evaluate_silence(
        buckets,
        now=now,
        last_document_at=now - timedelta(hours=5),
        monitoring_healthy=True,
    )
    assert result["state"] == "monitoring_unavailable"
    assert result.get("reason") == "gap_collection_not_continuously_healthy"
