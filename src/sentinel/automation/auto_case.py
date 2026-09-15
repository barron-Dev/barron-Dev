from __future__

"""Automatic case creation for Sentinel detections."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Mapping, Protocol, Sequence
from uuid import UUID, uuid4


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class Detection:
    detection_id: UUID
    tenant_id: UUID
    rule_id: str
    title: str
    severity: Severity
    observed_at: datetime
    source: str
    entity_type: str | None = None
    entity_id: str | None = None
    evidence: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.source.strip():
            raise ValueError("source must not be empty")


@dataclass(frozen=True, slots=True)
class Case:
    case_id: UUID
    tenant_id: UUID
    title: str
    severity: Severity
    status: CaseStatus
    created_at: datetime
    first_detected_at: datetime
    last_detected_at: datetime
    detection_ids: tuple[UUID, ...]
    rule_ids: tuple[str, ...]


class CaseRepository(Protocol):
    async def find_open_case(self, *, tenant_id: UUID, rule_id: str, entity_type: str | None, entity_id: str | None) -> Case | None: ...
    async def create_case(self, case: Case) -> Case: ...
    async def append_detection(self, *, case_id: UUID, detection: Detection) -> None: ...


@dataclass(frozen=True, slots=True)
class AutoCaseResult:
    case: Case
    created: bool


class AutoCaseEngine:
    """Idempotently create or enrich cases from actionable detections."""

    def __init__(self, repository: CaseRepository, *, minimum_severity: Severity = Severity.MEDIUM) -> None:
        self._repository = repository
        self._minimum_severity = minimum_severity

    async def process(self, detection: Detection) -> AutoCaseResult | None:
        if detection.severity < self._minimum_severity:
            return None

        existing = await self._repository.find_open_case(
            tenant_id=detection.tenant_id,
            rule_id=detection.rule_id,
            entity_type=detection.entity_type,
            entity_id=detection.entity_id,
        )
        if existing is not None:
            enriched = _enrich_case(existing, detection)
            await self._repository.append_detection(case_id=existing.case_id, detection=detection)
            return AutoCaseResult(case=enriched, created=False)

        observed = detection.observed_at
        case = Case(
            case_id=uuid4(),
            tenant_id=detection.tenant_id,
            title=detection.title,
            severity=detection.severity,
            status=CaseStatus.OPEN,
            created_at=datetime.now(timezone.utc),
            first_detected_at=observed,
            last_detected_at=observed,
            detection_ids=(detection.detection_id,),
            rule_ids=(detection.rule_id,),
        )
        persisted = await self._repository.create_case(case)
        await self._repository.append_detection(case_id=persisted.case_id, detection=detection)
        return AutoCaseResult(case=persisted, created=True)

    async def process_batch(self, detections: Sequence[Detection]) -> tuple[AutoCaseResult, ...]:
        results: list[AutoCaseResult] = []
        for detection in detections:
            result = await self.process(detection)
            if result is not None:
                results.append(result)
        return tuple(results)


def _enrich_case(case: Case, detection: Detection) -> Case:
    detection_ids = case.detection_ids if detection.detection_id in case.detection_ids else (*case.detection_ids, detection.detection_id)
    rule_ids = case.rule_ids if detection.rule_id in case.rule_ids else (*case.rule_ids, detection.rule_id)
    return Case(
        case_id=case.case_id,
        tenant_id=case.tenant_id,
        title=case.title,
        severity=max(case.severity, detection.severity),
        status=case.status,
        created_at=case.created_at,
        first_detected_at=min(case.first_detected_at, detection.observed_at),
        last_detected_at=max(case.last_detected_at, detection.observed_at),
        detection_ids=detection_ids,
        rule_ids=rule_ids,
    )
