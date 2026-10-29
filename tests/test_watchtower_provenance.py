from datetime import datetime, timedelta, timezone

import pytest

from cyclothone.watchtower.provenance import (
    EventEvidence,
    FrameProvenance,
    ModelProvenance,
    ObservationProvenance,
    ProvenanceValidationError,
    validate_event_support,
)


def _items():
    t = datetime(2026, 10, 29, 8, 0, tzinfo=timezone.utc)
    frame = FrameProvenance("tenant-a", "site-a", "camera-a", 1, t, "a" * 64, "ingest-1")
    model = ModelProvenance("person-detector", "1.2.0", "b" * 64, "onnxruntime", "1.22", "coco-2017")
    observation = ObservationProvenance(
        "tenant-a", "site-a", "camera-a", "obs-1", t + timedelta(milliseconds=50),
        frame, model, "person", 0.91, "run-1", (10.0, 20.0, 90.0, 180.0),
    )
    event = EventEvidence(
        "tenant-a", "site-a", "camera-a", "event-1", "loitering", "medium",
        t, t + timedelta(seconds=10), ("obs-1",), "loitering-v1", "1.0.0", "d" * 64,
    )
    return frame, model, observation, event


def test_event_support_requires_observation_in_same_tenant_site_camera_and_period():
    _, _, observation, event = _items()
    validate_event_support(event, (observation,))
    with pytest.raises(ProvenanceValidationError, match="scope_mismatch"):
        validate_event_support(event, (observation.__class__(
            tenant_id="tenant-b", site_id="site-a", camera_id="camera-a",
            observation_id="obs-1", observed_at=observation.observed_at,
            frame=observation.frame, model=observation.model, class_name="person",
            confidence=0.91, detector_run_id="run-1", box_xyxy=(10.0, 20.0, 90.0, 180.0),
        ),))


def test_frame_and_model_provenance_require_hashes_and_pinned_model_identity():
    frame, model, _, _ = _items()
    with pytest.raises(ProvenanceValidationError, match="frame_sha256"):
        FrameProvenance("tenant-a", "site-a", "camera-a", 1, frame.captured_at, "not-a-hash", "ingest-1")
    with pytest.raises(ProvenanceValidationError, match="model_id_required"):
        ModelProvenance("", "1.2.0", model.artifact_sha256, "onnxruntime", "1.22", "coco-2017")


def test_observation_cannot_precede_its_frame_or_claim_invalid_confidence():
    frame, model, observation, _ = _items()
    with pytest.raises(ProvenanceValidationError, match="precedes_frame"):
        ObservationProvenance(
            "tenant-a", "site-a", "camera-a", "obs-early",
            frame.captured_at - timedelta(seconds=1), frame, model, "person", 0.9,
            "run-1", (10.0, 20.0, 90.0, 180.0),
        )
    with pytest.raises(ProvenanceValidationError, match="confidence_invalid"):
        ObservationProvenance(
            "tenant-a", "site-a", "camera-a", "obs-bad", observation.observed_at,
            frame, model, "person", float("nan"), "run-1", (10.0, 20.0, 90.0, 180.0),
        )


def test_event_cannot_reference_missing_or_out_of_period_observations():
    _, _, observation, event = _items()
    with pytest.raises(ProvenanceValidationError, match="supporting_observation_missing"):
        validate_event_support(event, ())
    outside = observation.__class__(
        tenant_id=observation.tenant_id, site_id=observation.site_id, camera_id=observation.camera_id,
        observation_id=observation.observation_id, observed_at=event.ended_at + timedelta(seconds=1),
        frame=observation.frame, model=observation.model, class_name=observation.class_name,
        confidence=observation.confidence, detector_run_id=observation.detector_run_id,
        box_xyxy=observation.box_xyxy,
    )
    with pytest.raises(ProvenanceValidationError, match="outside_event_period"):
        validate_event_support(event, (outside,))
