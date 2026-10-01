import math

import pytest

from cyclothone.fusion.haversine import haversine_km, max_travel_km


def test_haversine_zero_distance():
    assert haversine_km(25.2048, 55.2708, 25.2048, 55.2708) == pytest.approx(0.0)


def test_haversine_rejects_invalid_coordinates():
    with pytest.raises(ValueError):
        haversine_km(91, 0, 0, 0)
    with pytest.raises(ValueError):
        haversine_km(0, 181, 0, 0)
    with pytest.raises(ValueError):
        haversine_km(math.nan, 0, 0, 0)


def test_travel_limit_is_deterministic():
    assert max_travel_km(3600, "walk") == pytest.approx(5.0)
    assert max_travel_km(3600, "vehicle") == pytest.approx(120.0)
    assert max_travel_km(3600, "plane") == pytest.approx(900.0)


def test_travel_limit_rejects_unknown_mode_and_negative_time():
    with pytest.raises(ValueError):
        max_travel_km(-1)
    with pytest.raises(ValueError):
        max_travel_km(60, "teleport")
