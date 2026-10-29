"""Provenance validation for Watchtower observations and events.

This module validates evidence metadata only. It does not produce detections;
callers must resolve source references against durable tenant-scoped storage.
"""
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProvenanceValidationError(ValueError):
    pass


def _text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ProvenanceValidationError(f"{field}_required")


def _hash(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProvenanceValidationError(f"{field}_must_be_sha256")


def _time(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProvenanceValidationError(f"{field}_must_be_timezone_aware")


@dataclass(frozen=True, slots=True)
class FrameProvenance:
    tenant_id: str
    site_id: str
    camera_id: str
    sequence: int
    captured_at: datetime
    sha256: str
    ingest_record_id: str

    def __post_init__(self):
        for field in ("tenant_id", "site_id", "camera_id", "ingest_record_id"):
            _text(getattr(self, field), field)
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise ProvenanceValidationError("sequence_must_be_positive_integer")
        _time(self.captured_at, "captured_at")
        _hash(self.sha256, "frame_sha256")


@dataclass(frozen=True, slots=True)
class ModelProvenance:
    model_id: str
    version: str
    artifact_sha256: str
    runtime: str
    runtime_version: str
    label_set_version: str

    def __post_init__(self):
        for field in ("model_id", "version", "runtime", "runtime_version", "label_set_version"):
            _text(getattr(self, field), field)
        _hash(self.artifact_sha256, "model_artifact_sha256")


@dataclass(frozen=True, slots=True)
class ObservationProvenance:
    tenant_id: str
    site_id: str
    camera_id: str
    observation_id: str
    observed_at: datetime
    frame: FrameProvenance
    model: ModelProvenance
    class_name: str
    confidence: float
    detector_run_id: str
    box_xyxy: tuple[float, float, float, float]

    def __post_init__(self):
        for field in ("tenant_id", "site_id", "camera_id", "observation_id", "class_name", "detector_run_id"):
            _text(getattr(self, field), field)
        _time(self.observed_at, "observed_at")
        if (self.tenant_id, self.site_id, self.camera_id) != (self.frame.tenant_id, self.frame.site_id, self.frame.camera_id):
            raise ProvenanceValidationError("observation_frame_scope_mismatch")
        if self.observed_at < self.frame.captured_at:
            raise ProvenanceValidationError("observation_precedes_frame")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ProvenanceValidationError("confidence_invalid")
        if len(self.box_xyxy) != 4 or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in self.box_xyxy):
            raise ProvenanceValidationError("box_must_have_four_finite_coordinates")
        x1, y1, x2, y2 = self.box_xyxy
        if x1 < 0 or y1 < 0 or x2 <= x1 or y2 <= y1:
            raise ProvenanceValidationError("box_coordinates_invalid")


@dataclass(frozen=True, slots=True)
class EventEvidence:
    tenant_id: str
    site_id: str
    camera_id: str
    event_id: str
    event_type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    started_at: datetime
    ended_at: datetime
    observation_ids: tuple[str, ...]
    rule_id: str
    rule_version: str
    evidence_bundle_sha256: str

    def __post_init__(self):
        for field in ("tenant_id", "site_id", "camera_id", "event_id", "event_type", "rule_id", "rule_version"):
            _text(getattr(self, field), field)
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ProvenanceValidationError("severity_invalid")
        _time(self.started_at, "started_at")
        _time(self.ended_at, "ended_at")
        if self.ended_at < self.started_at:
            raise ProvenanceValidationError("event_period_invalid")
        if not self.observation_ids or any(not isinstance(v, str) or not v.strip() for v in self.observation_ids):
            raise ProvenanceValidationError("supporting_observations_required")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ProvenanceValidationError("duplicate_observation_reference")
        _hash(self.evidence_bundle_sha256, "evidence_bundle_sha256")


def validate_event_support(event: EventEvidence, observations: tuple[ObservationProvenance, ...]) -> None:
    by_id = {item.observation_id: item for item in observations}
    if len(by_id) != len(observations):
        raise ProvenanceValidationError("duplicate_observation_record")
    for observation_id in event.observation_ids:
        item = by_id.get(observation_id)
        if item is None:
            raise ProvenanceValidationError("supporting_observation_missing")
        if (item.tenant_id, item.site_id, item.camera_id) != (event.tenant_id, event.site_id, event.camera_id):
            raise ProvenanceValidationError("event_observation_scope_mismatch")
        if not event.started_at <= item.observed_at <= event.ended_at:
            raise ProvenanceValidationError("observation_outside_event_period")
