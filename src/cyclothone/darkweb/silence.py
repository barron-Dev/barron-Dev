from __future__ import annotations

from datetime import UTC, datetime, timedelta
from math import exp, isfinite
from statistics import mean


BASELINE_DAYS = 56
MIN_VALID_HOURS_PER_SLOT = 4
MIN_COMPLETE_POLLS_PER_HOUR = 3
MIN_SILENCE_GAP_HOURS = 2.0
SILENCE_PVALUE_THRESHOLD = 0.01
COLLECTOR_FRESHNESS = timedelta(minutes=35)


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC)


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
        if int(row.get("complete_poll_count") or 0) < MIN_COMPLETE_POLLS_PER_HOUR:
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

    # Winsorize the upper 5% to keep a single burst from dominating the rate.
    counts = sorted(count for _, count in valid)
    cap_index = min(len(counts) - 1, int(0.95 * (len(counts) - 1)))
    cap = counts[cap_index]
    robust_rate = mean(min(count, cap) for count in counts)
    if robust_rate <= 0:
        return {
            "state": "no_expected_activity",
            "p_value": 1.0,
            "expected_rate_per_hour": 0.0,
            "baseline_bucket_count": len(valid),
        }

    # Convert variance to the negative-binomial size parameter r where possible.
    sample_mean = mean(counts)
    variance = sum((count - sample_mean) ** 2 for count in counts) / max(len(counts) - 1, 1)
    dispersion_size = None
    if variance > sample_mean * 1.05 and variance > robust_rate:
        dispersion_size = robust_rate * robust_rate / max(variance - robust_rate, 1e-9)
        dispersion_size = max(min(dispersion_size, 1e6), 1e-3)

    gap_hours = max((current - last_seen).total_seconds() / 3600.0, 0.0)
    p_value = silence_pvalue(last_seen, current, robust_rate, dispersion_size)
    candidate = gap_hours >= MIN_SILENCE_GAP_HOURS and p_value <= SILENCE_PVALUE_THRESHOLD
    return {
        "state": "silence_candidate" if candidate else "normal",
        "p_value": p_value,
        "expected_rate_per_hour": robust_rate,
        "dispersion_size": dispersion_size,
        "gap_hours": gap_hours,
        "baseline_bucket_count": len(valid),
        "baseline_start": min(t for t, _ in valid).isoformat(),
        "baseline_end": max(t for t, _ in valid).isoformat(),
        "shadow_only": True,
    }
