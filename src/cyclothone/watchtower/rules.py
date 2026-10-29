"""Deterministic rules over real, timestamped edge observations.

This module deliberately does not decode video or claim to detect objects. A
trusted, configured detector/tracker must supply observations from real media.
Rules return events only when the supplied observations prove the configured
condition; gaps and insufficient coverage remain explicit.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable


def _aware_utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field}_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class TrackObservation:
    """One real tracker observation; coordinates are optional and never inferred."""
    tenant_id: str
    camera_id: str
    track_id: str
    zone_id: str
    observed_at: datetime
    detector_id: str
    frame_sha256: str
    source_sequence: int

    def __post_init__(self) -> None:
        for field in ("tenant_id", "camera_id", "track_id", "zone_id", "detector_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field}_required")
        digest = self.frame_sha256
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("frame_sha256_must_be_lowercase_sha256")
        if isinstance(self.source_sequence, bool) or not isinstance(self.source_sequence, int) or self.source_sequence < 0:
            raise ValueError("source_sequence_must_be_nonnegative_integer")
        _aware_utc(self.observed_at, "observed_at")


@dataclass(frozen=True, slots=True)
class RuleEvent:
    tenant_id: str
    camera_id: str
    track_id: str
    zone_id: str
    event_type: str
    started_at: datetime
    confirmed_at: datetime
    duration_seconds: int
    evidence_frame_hashes: tuple[str, ...]
    rule_version: str


def evaluate_loitering(
    observations: Iterable[TrackObservation],
    *,
    threshold: timedelta = timedelta(seconds=300),
    max_observation_gap: timedelta = timedelta(seconds=15),
    rule_version: str = "loitering.v1",
) -> list[RuleEvent]:
    """Emit loitering events only for continuous observations in one zone.

    Observations must be actual output from an authorized edge detector/tracker.
    A gap greater than max_observation_gap breaks continuity; the algorithm
    will not bridge missing footage. Each camera/track/zone emits at most once
    per continuous segment. Results are deterministic for the same input.
    """
    if threshold <= timedelta(0):
        raise ValueError("threshold_must_be_positive")
    if max_observation_gap <= timedelta(0):
        raise ValueError("max_observation_gap_must_be_positive")
    if not rule_version or not rule_version.strip():
        raise ValueError("rule_version_required")

    ordered = sorted(
        observations,
        key=lambda o: (
            o.tenant_id, o.camera_id, o.track_id, o.zone_id,
            _aware_utc(o.observed_at, "observed_at"), o.source_sequence,
        ),
    )
    state: dict[tuple[str, str, str, str], dict] = {}
    events: list[RuleEvent] = []
    for obs in ordered:
        key = (obs.tenant_id, obs.camera_id, obs.track_id, obs.zone_id)
        now = _aware_utc(obs.observed_at, "observed_at")
        current = state.get(key)
        if current is None or now <= current["last_at"] or now - current["last_at"] > max_observation_gap:
            state[key] = {"start": now, "last_at": now, "hashes": [obs.frame_sha256], "emitted": False}
            continue
        current["last_at"] = now
        if obs.frame_sha256 not in current["hashes"]:
            current["hashes"].append(obs.frame_sha256)
        elapsed = now - current["start"]
        if elapsed >= threshold and not current["emitted"]:
            events.append(RuleEvent(
                tenant_id=obs.tenant_id,
                camera_id=obs.camera_id,
                track_id=obs.track_id,
                zone_id=obs.zone_id,
                event_type="loitering",
                started_at=current["start"],
                confirmed_at=now,
                duration_seconds=int(elapsed.total_seconds()),
                evidence_frame_hashes=tuple(current["hashes"]),
                rule_version=rule_version,
            ))
            current["emitted"] = True
    return events


def coverage_outcome(*, source_available: bool, frames_observed: int, gaps: Iterable[str]) -> str:
    """Never report 'clear' when a source is unavailable or has coverage gaps."""
    gap_list = tuple(gaps)
    if frames_observed < 0:
        raise ValueError("frames_observed_must_be_nonnegative")
    if not source_available or frames_observed == 0:
        return "unavailable"
    if gap_list:
        return "partial_coverage"
    return "complete"
