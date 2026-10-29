"""Anonymous constant-velocity forecast primitives for zone-safety events.

Coordinates are caller-defined image or calibrated-world coordinates. This module does
not identify people, infer intent, or assert a crime. Every forecast is uncertain and
requires human review.
"""
from dataclasses import dataclass
import math


@dataclass(frozen=True, slots=True)
class Point:
    x: float
    y: float
    observed_at_s: float


@dataclass(frozen=True, slots=True)
class Prediction:
    x: float
    y: float
    horizon_s: float
    speed_units_s: float
    uncertainty_radius: float
    coverage_status: str
    coverage_gaps: tuple[str, ...]


def predict_constant_velocity(observations: tuple[Point, ...], *, horizon_s: float = 3.0,
                              max_gap_s: float = 2.0,
                              max_speed_units_s: float = 10_000.0) -> Prediction:
    if not 0 < horizon_s <= 10:
        raise ValueError("horizon_must_be_between_0_and_10_seconds")
    if not 0 < max_gap_s <= 30:
        raise ValueError("invalid_max_gap")
    if len(observations) < 2:
        raise ValueError("at_least_two_observations_required")
    a, b = observations[-2:]
    if not all(math.isfinite(v) for v in (a.x, a.y, a.observed_at_s, b.x, b.y, b.observed_at_s)):
        raise ValueError("observations_must_be_finite")
    dt = b.observed_at_s - a.observed_at_s
    if dt <= 0:
        raise ValueError("timestamps_must_increase")
    if dt > max_gap_s:
        raise ValueError("observation_gap_exceeds_limit")
    vx, vy = (b.x - a.x) / dt, (b.y - a.y) / dt
    speed = math.hypot(vx, vy)
    if speed > max_speed_units_s:
        raise ValueError("implausible_speed")
    uncertainty = max(0.5, speed * 0.15) * horizon_s
    return Prediction(b.x + vx * horizon_s, b.y + vy * horizon_s, horizon_s, speed,
                      uncertainty, "partial_coverage",
                      ("constant_velocity_model_uncalibrated",))


def point_in_polygon(point: tuple[float, float],
                     polygon: tuple[tuple[float, float], ...]) -> bool:
    """Ray casting with conservative boundary inclusion."""
    x, y = point
    if len(polygon) < 3 or not all(math.isfinite(v) for v in (x, y)):
        raise ValueError("invalid_point_or_polygon")
    if any(not math.isfinite(v) for p in polygon for v in p):
        raise ValueError("polygon_coordinates_must_be_finite")
    inside, j = False, len(polygon) - 1
    for i, (xi, yi) in enumerate(polygon):
        xj, yj = polygon[j]
        cross = (x - xi) * (yj - yi) - (y - yi) * (xj - xi)
        if abs(cross) <= 1e-9 and min(xi, xj)-1e-9 <= x <= max(xi, xj)+1e-9 and min(yi, yj)-1e-9 <= y <= max(yi, yj)+1e-9:
            return True
        if (yi > y) != (yj > y) and x < (xj-xi) * (y-yi) / (yj-yi) + xi:
            inside = not inside
        j = i
    return inside


def forecast_zone_intersection(prediction: Prediction,
                               polygon: tuple[tuple[float, float], ...]) -> dict:
    """Emit a review-required forecast, never an actuator command."""
    return {
        "event_type": "trajectory_zone_forecast",
        "forecast_intersects_zone": point_in_polygon((prediction.x, prediction.y), polygon),
        "predicted_position": {"x": prediction.x, "y": prediction.y},
        "horizon_s": prediction.horizon_s,
        "uncertainty_radius": prediction.uncertainty_radius,
        "coverage_status": prediction.coverage_status,
        "coverage_gaps": list(prediction.coverage_gaps),
        "requires_human_review": True,
        "automatic_actuation_permitted": False,
    }
