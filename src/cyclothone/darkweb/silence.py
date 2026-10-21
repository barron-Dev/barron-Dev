from __future__ import annotations

from datetime import UTC, datetime, timedelta
from math import exp, isfinite
from statistics import mean, median


BASELINE_DAYS = 56
MIN_VALID_HOURS_PER_SLOT = 4
MIN_COMPLETE_POLLS_PER_HOUR = 3
MIN_SILENCE_GAP_HOURS = 2.0
SILENCE_PVALUE_THRESHOLD = 0.01

def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC)


def derive_cursor_delta(post_ids: list[int], previous_cursor: int | None) -> dict:
    """Count new visible Telegram posts only when the previous cursor is still visible."""
    ids = sorted({int(value) for value in post_ids if int(value) > 0})
    if not ids:
        return {
            "cursor_value": previous_cursor,
            "documents_new": None,
            "count_complete": False,
            "error_code": "telegram_message_parse_empty",
        }
    current_cursor = max(ids)
    if previous_cursor is None:
        return {
            "cursor_value": current_cursor,
            "documents_new": None,
            "count_complete": False,
            "error_code": "cursor_initialized",
        }
    if previous_cursor not in ids:
        # Do not advance across an unobserved window: doing so would let the next
        # poll count as complete after silently skipping unseen posts.
        return {
            "cursor_value": previous_cursor,
            "documents_new": None,
            "count_complete": False,
            "error_code": "cursor_not_visible",
        }
    return {
        "cursor_value": current_cursor,
        "documents_new": sum(1 for value in ids if value > previous_cursor),
        "count_complete": True,
        "error_code": None,
    }


def silence_pvalue(
    last_document_at: datetime | str,
    now: datetime | str,
    expected_rate_per_hour: float,
    dispersion_size: float | None = None,
) -> float:
    """Probability of observing zero new documents over the current gap.

    dispersion_size is the negative-binomial size parameter r, not a
    variance/mean ratio. None means use the Poisson model.
    """
    last_seen = _as_utc(last_document_at)
    current = _as_utc(now)
    gap_hours = max((current - last_seen).total_seconds() / 3600.0, 0.0)
    rate = max(float(expected_rate_per_hour), 0.0)
    lam = rate * gap_hours
    if rate == 0.0:
        return 1.0
    if dispersion_size is None or not isfinite(dispersion_size) or dispersion_size <= 0:
        return exp(-lam)
    size = float(dispersion_size)
    return (size / (size + lam)) ** size


def _hour_of_week(value: datetime) -> int:
    utc = _as_utc(value)
    return utc.weekday() * 24 + utc.hour


def zero_arrival_probability(expected_count: float, dispersion_size: float | None = None) -> float:
    """P(N=0) for an expected count, using Poisson or negative-binomial dispersion."""
    lam = max(float(expected_count), 0.0)
    if dispersion_size is None or not isfinite(dispersion_size) or dispersion_size <= 0:
        return exp(-lam)
    size = float(dispersion_size)
    return (size / (size + lam)) ** size


def _expected_count_over_gap(
    last_seen: datetime,
    current: datetime,
    slot_rates: dict[int, float],
) -> float:
    """Integrate the seasonal hourly baseline over the exact observed gap."""
    cursor = _as_utc(last_seen)
    end_time = _as_utc(current)
    expected = 0.0
    while cursor < end_time:
        next_hour = cursor.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        segment_end = min(next_hour, end_time)
        fraction = (segment_end - cursor).total_seconds() / 3600.0
        expected += max(slot_rates.get(_hour_of_week(cursor), 0.0), 0.0) * fraction
        cursor = segment_end
    return expected


def evaluate_silence(
    buckets: list[dict],
    *,
    now: datetime,
    last_document_at: datetime | None,
    monitoring_healthy: bool,
) -> dict:
    """Return a shadow-only state; this function never creates a customer alert.

    Buckets must be derived from actual collector observations. A bucket is
    eligible only when it has at least three complete polls and no failed poll.
    """
    current = _as_utc(now)
    last_seen = _as_utc(last_document_at) if last_document_at is not None else None
    if not monitoring_healthy:
        return {"state": "monitoring_unavailable", "p_value": None, "baseline_bucket_count": 0}
    if last_seen is None:
        return {"state": "insufficient_baseline", "p_value": None, "baseline_bucket_count": 0}

    valid = []
    for row in buckets:
        bucket_time = _as_utc(row["bucket_hour"])
        if bucket_time > current or bucket_time < current - timedelta(days=BASELINE_DAYS):
            continue
        poll_count = int(row.get("poll_count") or 0)
        complete_poll_count = int(row.get("complete_poll_count") or 0)
        if complete_poll_count < MIN_COMPLETE_POLLS_PER_HOUR:
            continue
        # Unknown/failed polls invalidate the entire hour; partial counts must not
        # silently lower the baseline and manufacture a quiet-source signal.
        if poll_count != complete_poll_count:
            continue
        if int(row.get("failed_poll_count") or 0) != 0:
            continue
        valid.append((bucket_time, max(0, int(row.get("documents_new_sum") or 0))))

    if not valid:
        return {"state": "insufficient_baseline", "p_value": None, "baseline_bucket_count": 0}
    span = max(t for t, _ in valid) - min(t for t, _ in valid)
    if span < timedelta(days=BASELINE_DAYS - 1):
        return {
            "state": "insufficient_baseline",
            "p_value": None,
            "baseline_bucket_count": len(valid),
            "baseline_span_hours": span.total_seconds() / 3600.0,
        }

    slots: dict[int, list[int]] = {}
    for stamp, count in valid:
        slots.setdefault(_hour_of_week(stamp), []).append(count)
    if any(len(slots.get(slot, [])) < MIN_VALID_HOURS_PER_SLOT for slot in range(168)):
        return {
            "state": "insufficient_baseline",
            "p_value": None,
            "baseline_bucket_count": len(valid),
            "hour_of_week_slots_ready": sum(len(slots.get(slot, [])) >= MIN_VALID_HOURS_PER_SLOT for slot in range(168)),
        }

    # A quiet-source claim is invalid if any complete hour in the observed gap
    # lacks enough successful polls or contains a failed poll. Partial boundary
    # hours are excluded rather than guessed.
    bucket_by_hour = {
        _as_utc(row["bucket_hour"]).replace(minute=0, second=0, microsecond=0): row
        for row in buckets
    }
    first_full_hour = last_seen.replace(minute=0, second=0, microsecond=0)
    if first_full_hour < last_seen:
        first_full_hour += timedelta(hours=1)
    end_full_hour = current.replace(minute=0, second=0, microsecond=0)
    check_hour = first_full_hour
    while check_hour < end_full_hour:
        gap_bucket = bucket_by_hour.get(check_hour)
        if (
            gap_bucket is None
            or int(gap_bucket.get("complete_poll_count") or 0) < MIN_COMPLETE_POLLS_PER_HOUR
            or int(gap_bucket.get("poll_count") or 0) != int(gap_bucket.get("complete_poll_count") or 0)
            or int(gap_bucket.get("failed_poll_count") or 0) != 0
        ):
            return {
                "state": "monitoring_unavailable",
                "p_value": None,
                "baseline_bucket_count": 0,
                "reason": "gap_collection_not_continuously_healthy",
                "unhealthy_hour": check_hour.isoformat(),
            }
        check_hour += timedelta(hours=1)

    # Estimate the global rate from the 168 seasonal slot means, not the
    # pooled 95th percentile: pooled clipping would erase legitimate activity
    # from low-volume sources whose publishing is concentrated in a few slots.
    counts = sorted(count for _, count in valid)
    slot_means: dict[int, float] = {}
    for slot, values in slots.items():
        slot_median = median(values)
        slot_mad = median(abs(value - slot_median) for value in values)
        # A single isolated spike with otherwise-zero history is not a rate.
        # Stable recurring low-volume publishing is retained because its median
        # is positive; MAD limits outlier influence within each seasonal slot.
        cap = slot_median + 3.0 * slot_mad
        slot_means[slot] = mean(min(value, cap) for value in values)
    robust_rate = mean(slot_means.values()) if slot_means else 0.0
    if robust_rate <= 0:
        return {
            "state": "no_expected_activity",
            "p_value": 1.0,
            "expected_rate_per_hour": 0.0,
            "expected_count": 0.0,
            "baseline_bucket_count": len(valid),
        }

    slot_rates: dict[int, float] = {}
    for slot, values in slots.items():
        slot_rate = slot_means[slot]
        weight = len(values) / (len(values) + MIN_VALID_HOURS_PER_SLOT)
        slot_rates[slot] = weight * slot_rate + (1.0 - weight) * robust_rate

    # Estimate over-dispersion from the full valid hourly series.
    sample_mean = mean(counts)
    variance = sum((count - sample_mean) ** 2 for count in counts) / max(len(counts) - 1, 1)
    dispersion_size = None
    if variance > sample_mean * 1.05 and variance > robust_rate:
        dispersion_size = robust_rate * robust_rate / max(variance - robust_rate, 1e-9)
        dispersion_size = max(min(dispersion_size, 1e6), 1e-3)

    gap_hours = max((current - last_seen).total_seconds() / 3600.0, 0.0)
    expected_count = _expected_count_over_gap(last_seen, current, slot_rates)
    p_value = zero_arrival_probability(expected_count, dispersion_size)
    expected_rate = expected_count / gap_hours if gap_hours > 0 else 0.0
    candidate = gap_hours >= MIN_SILENCE_GAP_HOURS and p_value <= SILENCE_PVALUE_THRESHOLD
    return {
        "state": "silence_candidate" if candidate else "normal",
        "p_value": p_value,
        "expected_rate_per_hour": expected_rate,
        "expected_count": expected_count,
        "dispersion_size": dispersion_size,
        "gap_hours": gap_hours,
        "baseline_bucket_count": len(valid),
        "baseline_start": min(t for t, _ in valid).isoformat(),
        "baseline_end": max(t for t, _ in valid).isoformat(),
        "shadow_only": True,
    }
