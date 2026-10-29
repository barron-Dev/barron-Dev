"""Typed, modality-aware evidence manifests for Omni-Vision."""
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

HASH = re.compile(r"^[0-9a-f]{64}$")
MODALITIES = {"cam", "file", "audio", "doc", "env"}
COVERAGE = {"complete", "partial_coverage", "unavailable"}


def utc(value: str, field: str) -> str:
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field}_must_be_timestamp") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError(f"{field}_must_include_timezone")
    return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    tenant_id: str
    source_id: str
    modality: str
    event_type: str
    source_media_sha256: str
    observed_at: str
    ingested_at: str
    detector_name: str
    detector_version: str
    runtime_sha256: str
    configuration_sha256: str
    artifact_sha256: str | None = None
    captured_at: str | None = None
    model_sha256: str | None = None
    coverage_status: str = "complete"
    coverage_gaps: tuple[str, ...] = ()
    attributes: Mapping[str, Any] | None = None

    def __post_init__(self):
        for field in ("tenant_id", "source_id", "event_type", "detector_name", "detector_version"):
            if not isinstance(getattr(self, field), str) or not getattr(self, field).strip():
                raise ValueError(f"{field}_required")
        if self.modality not in MODALITIES:
            raise ValueError("unsupported_modality")
        if self.coverage_status not in COVERAGE:
            raise ValueError("invalid_coverage_status")
        for field in ("source_media_sha256", "runtime_sha256", "configuration_sha256"):
            if not HASH.fullmatch(getattr(self, field) or ""):
                raise ValueError(f"{field}_must_be_sha256")
        for field in ("artifact_sha256", "model_sha256"):
            value = getattr(self, field)
            if value is not None and not HASH.fullmatch(value):
                raise ValueError(f"{field}_must_be_sha256")
        utc(self.observed_at, "observed_at")
        utc(self.ingested_at, "ingested_at")
        if self.captured_at is not None:
            utc(self.captured_at, "captured_at")
        if self.coverage_status == "partial_coverage" and not self.coverage_gaps:
            raise ValueError("partial_coverage_requires_gap")
        if self.coverage_status == "complete" and self.coverage_gaps:
            raise ValueError("complete_coverage_cannot_have_gaps")

    def to_payload(self) -> dict[str, Any]:
        data = asdict(self)
        for field in ("observed_at", "ingested_at"):
            data[field] = utc(getattr(self, field), field)
        if self.captured_at is not None:
            data["captured_at"] = utc(self.captured_at, "captured_at")
        data["coverage_gaps"] = list(self.coverage_gaps)
        data["attributes"] = dict(self.attributes or {})
        return data
