import pytest
from cyclothone.vision.trajectory import (
    Point, forecast_zone_intersection, point_in_polygon, predict_constant_velocity,
)


def test_prediction_forecast_requires_review():
    prediction = predict_constant_velocity((Point(0, 0, 1), Point(2, 0, 2)))
    result = forecast_zone_intersection(prediction, ((4, -1), (7, -1), (7, 1), (4, 1)))
    assert result["forecast_intersects_zone"] is True
    assert result["requires_human_review"] is True
    assert result["automatic_actuation_permitted"] is False
    assert result["coverage_status"] == "partial_coverage"


def test_non_increasing_timestamps_rejected():
    with pytest.raises(ValueError, match="timestamps_must_increase"):
        predict_constant_velocity((Point(0, 0, 1), Point(1, 1, 1)))


def test_stale_observations_rejected():
    with pytest.raises(ValueError, match="observation_gap_exceeds_limit"):
        predict_constant_velocity((Point(0, 0, 1), Point(1, 1, 5)))


def test_zone_boundary_is_conservatively_inside():
    assert point_in_polygon((0, 0), ((0, 0), (2, 0), (2, 2), (0, 2)))
