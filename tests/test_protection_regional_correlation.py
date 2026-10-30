from datetime import datetime, timedelta, timezone

import pytest

from cyclothone.protection.regional_correlation import regional_temporal_intersection


def test_same_region_inside_assignment_window_matches_with_zero_delta():
    start = datetime(2026, 11, 10, 9, tzinfo=timezone.utc)
    end = start + timedelta(days=2)
    matched, delta = regional_temporal_intersection("GB-LON", start, end, "GB-LON", start + timedelta(hours=4))
    assert matched is True
    assert delta == 0


def test_same_region_within_48_hour_boundary_matches():
    start = datetime(2026, 11, 10, 9, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    matched, delta = regional_temporal_intersection(
        "FR-PAR", start, end, "FR-PAR", start - timedelta(hours=48)
    )
    assert matched is True
    assert delta == 48 * 3600


def test_region_mismatch_or_out_of_window_does_not_match():
    start = datetime(2026, 11, 10, 9, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    assert regional_temporal_intersection("GB-LON", start, end, "FR-PAR", start)[0] is False
    assert regional_temporal_intersection(
        "GB-LON", start, end, "GB-LON", end + timedelta(hours=48, seconds=1)
    ) == (False, None)


def test_naive_timestamps_and_invalid_windows_are_rejected():
    start = datetime(2026, 11, 10, 9)
    with pytest.raises(ValueError):
        regional_temporal_intersection("GB-LON", start, start + timedelta(days=1), "GB-LON", start)
