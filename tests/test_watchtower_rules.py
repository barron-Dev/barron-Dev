from datetime import datetime, timedelta, timezone

import pytest

from cyclothone.watchtower.rules import TrackObservation, coverage_outcome, evaluate_loitering
from cyclothone.watchtower.reports import ReportEvent, build_report_payload


T0 = datetime(2026, 10, 29, 8, 0, tzinfo=timezone.utc)


def observation(seconds: int, seq: int | None = None, *, zone: str = "zone-a", digest: str | None = None):
    sequence = seconds if seq is None else seq
    return TrackObservation(
        tenant_id="tenant-real-boundary",
        camera_id="camera-1",
        track_id="track-7",
        zone_id=zone,
        observed_at=T0 + timedelta(seconds=seconds),
        detector_id="edge-detector-1",
        frame_sha256=digest or f"{sequence:064x}",
        source_sequence=sequence,
    )


def test_loitering_emits_once_after_continuous_threshold():
    events = evaluate_loitering(
        [observation(0), observation(10), observation(20), observation(300)],
        threshold=timedelta(seconds=300),
        max_observation_gap=timedelta(seconds=300),
    )
    assert len(events) == 1
    assert events[0].event_type == "loitering"
    assert events[0].duration_seconds == 300
    assert len(events[0].evidence_frame_hashes) == 4


def test_missing_observation_gap_breaks_continuity():
    events = evaluate_loitering(
        [observation(0), observation(10), observation(600)],
        threshold=timedelta(seconds=300),
        max_observation_gap=timedelta(seconds=15),
    )
    assert events == []


def test_zone_change_and_return_resets_dwell_time():
    events = evaluate_loitering(
        [observation(0, zone="zone-a"), observation(200, zone="zone-b"),
         observation(250, zone="zone-a"), observation(400, zone="zone-a")],
        threshold=timedelta(seconds=300),
        max_observation_gap=timedelta(seconds=300),
    )
    assert events == []


def test_zone_change_does_not_join_dwell_time():
    events = evaluate_loitering(
        [observation(0, zone="zone-a"), observation(200, zone="zone-b")],
        threshold=timedelta(seconds=100),
        max_observation_gap=timedelta(seconds=300),
    )
    assert events == []


def test_rejects_naive_timestamps_and_invalid_hashes():
    with pytest.raises(ValueError, match="timezone_aware"):
        TrackObservation(
            tenant_id="t", camera_id="c", track_id="p", zone_id="z",
            observed_at=datetime(2026, 1, 1), detector_id="d",
            frame_sha256="a" * 64, source_sequence=1,
        )
    with pytest.raises(ValueError, match="lowercase_sha256"):
        TrackObservation("t", "c", "p", "z", T0, "d", "NOT_A_HASH", 1)


def test_coverage_never_equates_unavailable_source_with_clear():
    assert coverage_outcome(source_available=False, frames_observed=0, gaps=[]) == "unavailable"
    assert coverage_outcome(source_available=True, frames_observed=12, gaps=["stream_disconnected"]) == "partial_coverage"
    assert coverage_outcome(source_available=True, frames_observed=12, gaps=[]) == "complete"
    with pytest.raises(ValueError, match="nonnegative_integer"):
        coverage_outcome(source_available=True, frames_observed=-1, gaps=[])


def test_report_is_data_only_and_does_not_claim_threat_free():
    payload = build_report_payload(
        report_id="r-1",
        tenant_id="tenant-1",
        camera_group_id="group-1",
        report_type="brief",
        language_code="en",
        period_start=T0,
        period_end=T0 + timedelta(hours=1),
        events=[ReportEvent("loitering", T0 + timedelta(minutes=5), "camera-1", ("a" * 64,))],
        source_coverage="partial_coverage",
        coverage_gaps=["camera_disconnected"],
    )
    assert payload["event_count"] == 1
    assert payload["claims"]["threat_free"] is False
    assert payload["source_coverage"] == "partial_coverage"


def test_partial_report_requires_explicit_gap():
    with pytest.raises(ValueError, match="partial_coverage_requires_gaps"):
        build_report_payload(
            report_id="r-1", tenant_id="t", camera_group_id="g", report_type="brief",
            language_code="en", period_start=T0, period_end=T0 + timedelta(hours=1),
            events=[], source_coverage="partial_coverage", coverage_gaps=[],
        )
