from __future__ import annotations

import math

_EARTH_RADIUS_KM = 6371.0088
_SPEEDS_KMH = {"walk": 5.0, "vehicle": 120.0, "plane": 900.0}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    values = (lat1, lon1, lat2, lon2)
    if not all(math.isfinite(v) for v in values):
        raise ValueError("coordinates must be finite")
    if not -90 <= lat1 <= 90 or not -90 <= lat2 <= 90:
        raise ValueError("latitude out of range")
    if not -180 <= lon1 <= 180 or not -180 <= lon2 <= 180:
        raise ValueError("longitude out of range")
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(min(1.0, max(0.0, a))))


def max_travel_km(elapsed_seconds: int, mode: str = "vehicle") -> float:
    if not isinstance(elapsed_seconds, int) or isinstance(elapsed_seconds, bool) or elapsed_seconds < 0:
        raise ValueError("elapsed_seconds must be a non-negative integer")
    try:
        speed = _SPEEDS_KMH[mode]
    except KeyError as exc:
        raise ValueError("unsupported travel mode") from exc
    return speed * elapsed_seconds / 3600.0
