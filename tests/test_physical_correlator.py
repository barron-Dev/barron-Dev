from datetime import datetime, timezone

from sentinel.physical.correlator import PhysicalCorrelator


def test_parse_ts_handles_z_suffix():
    assert PhysicalCorrelator._parse_ts("2026-09-16T10:00:00Z") is not None


def test_parse_ts_rejects_invalid():
    assert PhysicalCorrelator._parse_ts("not-a-date") is None
    assert PhysicalCorrelator._parse_ts(None) is None


def test_after_hours_boundaries():
    assert datetime(2026, 9, 16, 22, tzinfo=timezone.utc).hour >= 20
    assert 6 <= datetime(2026, 9, 16, 14, tzinfo=timezone.utc).hour < 20


def test_uuid_validation():
    assert PhysicalCorrelator._is_uuid("00000000-0000-0000-0000-000000000001")
    assert not PhysicalCorrelator._is_uuid("not-a-uuid")
