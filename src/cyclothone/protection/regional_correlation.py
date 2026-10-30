from __future__ import annotations

from datetime import datetime, timedelta


def regional_temporal_intersection(
    assignment_region: str,
    assignment_start: datetime,
    assignment_end: datetime,
    event_region: str,
    event_at: datetime,
    *,
    window: timedelta = timedelta(hours=48),
) -> tuple[bool, int | None]:
    """Exact region + bounded time intersection; never estimates personal proximity or intent."""
    values = (assignment_start, assignment_end, event_at)
    if any(value.tzinfo is None or value.utcoffset() is None for value in values):
        raise ValueError("all timestamps must be timezone-aware")
    if assignment_end <= assignment_start or window < timedelta(0):
        raise ValueError("invalid assignment interval or correlation window")
    if not assignment_region or assignment_region != event_region:
        return False, None
    if event_at < assignment_start - window or event_at > assignment_end + window:
        return False, None
    if event_at < assignment_start:
        delta = int((assignment_start - event_at).total_seconds())
    elif event_at > assignment_end:
        delta = int((event_at - assignment_end).total_seconds())
    else:
        delta = 0
    return True, delta
