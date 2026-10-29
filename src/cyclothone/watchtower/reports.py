"""Deterministic Watchtower report contracts; no free-form LLM narration."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


REPORT_TYPES = frozenset({"brief", "detailed", "full"})
COVERAGE = frozenset({"complete", "partial_coverage", "unavailable"})


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ReportEvent:
    event_type: str
    observed_at: datetime
    camera_id: str
    evidence_hashes: tuple[str, ...]
    source_status: str = "complete"

    def __post_init__(self) -> None:
        if not self.event_type or not self.camera_id:
            raise ValueError("event_type_and_camera_id_required")
        if self.source_status not in COVERAGE:
            raise ValueError("invalid_source_status")
        for digest in self.evidence_hashes:
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("evidence_hash_must_be_lowercase_sha256")
        _timestamp(self.observed_at)


def build_report_payload(
    *,
    report_id: str,
    tenant_id: str,
    camera_group_id: str,
    report_type: str,
    language_code: str,
    period_start: datetime,
    period_end: datetime,
    events: Iterable[ReportEvent],
    source_coverage: str,
    coverage_gaps: Iterable[str],
) -> dict:
    """Build a data-only report payload; rendering and delivery are separate.

    No 'no threats detected' assertion is generated. The report says only what
    the observed event records and explicit source coverage support.
    """
    if not all(isinstance(v, str) and v.strip() for v in (
        report_id, tenant_id, camera_group_id, language_code
    )):
        raise ValueError("report_identity_fields_required")
    if report_type not in REPORT_TYPES:
        raise ValueError("invalid_report_type")
    if source_coverage not in COVERAGE:
        raise ValueError("invalid_source_coverage")
    start, end = _timestamp(period_start), _timestamp(period_end)
    if period_end <= period_start:
        raise ValueError("period_end_must_follow_period_start")
    gaps = sorted(set(coverage_gaps))
    if source_coverage == "complete" and gaps:
        raise ValueError("complete_coverage_cannot_have_gaps")
    if source_coverage == "partial_coverage" and not gaps:
        raise ValueError("partial_coverage_requires_gaps")
    rows = []
    for event in events:
        stamp = _timestamp(event.observed_at)
        if stamp < start or stamp > end:
            raise ValueError("event_outside_report_period")
        rows.append({
            "event_type": event.event_type,
            "observed_at": stamp,
            "camera_id": event.camera_id,
            "evidence_hashes": list(event.evidence_hashes),
            "source_status": event.source_status,
        })
    rows.sort(key=lambda r: (r["observed_at"], r["camera_id"], r["event_type"]))
    return {
        "schema": "cyclothone.watchtower.report.v1",
        "report_id": report_id,
        "tenant_id": tenant_id,
        "camera_group_id": camera_group_id,
        "report_type": report_type,
        "language_code": language_code,
        "period_start": start,
        "period_end": end,
        "generated_at": _timestamp(datetime.now(timezone.utc)),
        "source_coverage": source_coverage,
        "coverage_gaps": gaps,
        "event_count": len(rows),
        "events": rows,
        "claims": {
            "threat_free": False,
            "meaning": "No threat-free conclusion is inferred from absence of recorded events."
        },
    }
