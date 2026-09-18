from __future__ import annotations

"""Automatic case creation and optional hand-off to the unified response chain."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Any, Mapping, Protocol, Sequence
from uuid import UUID, uuid4

from cyclothone.response.orchestrator import ActionClass, ACTION_CLASS, ActionPlan, ResponseOrchestrator


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
        if not self.rule_id.strip(): raise ValueError("rule_id must not be empty")
        if not self.title.strip(): raise ValueError("title must not be empty")
        if not self.source.strip(): raise ValueError("source must not be empty")


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
    """Idempotently create/enrich cases and hand newly-created cases to response."""

    def __init__(self, repository: CaseRepository, *, minimum_severity: Severity = Severity.MEDIUM, orchestrator: ResponseOrchestrator | None = None) -> None:
        self._repository = repository
        self._minimum_severity = minimum_severity
        self._orchestrator = orchestrator

    async def process(self, detection: Detection, rule: Mapping[str, Any] | None = None) -> AutoCaseResult | None:
        if detection.severity < self._minimum_severity:
            return None
        existing = await self._repository.find_open_case(tenant_id=detection.tenant_id, rule_id=detection.rule_id, entity_type=detection.entity_type, entity_id=detection.entity_id)
        if existing is not None:
            enriched = _enrich_case(existing, detection)
            await self._repository.append_detection(case_id=existing.case_id, detection=detection)
            return AutoCaseResult(case=enriched, created=False)

        observed = detection.observed_at
        case = Case(case_id=uuid4(), tenant_id=detection.tenant_id, title=detection.title, severity=detection.severity, status=CaseStatus.OPEN, created_at=datetime.now(timezone.utc), first_detected_at=observed, last_detected_at=observed, detection_ids=(detection.detection_id,), rule_ids=(detection.rule_id,))
        persisted = await self._repository.create_case(case)
        await self._repository.append_detection(case_id=persisted.case_id, detection=detection)
        if self._orchestrator and rule:
            await self._run_response(persisted, detection, rule)
        return AutoCaseResult(case=persisted, created=True)

    async def process_batch(self, detections: Sequence[Detection], rules: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[AutoCaseResult, ...]:
        results: list[AutoCaseResult] = []
        for detection in detections:
            result = await self.process(detection, (rules or {}).get(detection.rule_id))
            if result is not None: results.append(result)
        return tuple(results)

    async def _run_response(self, case: Case, detection: Detection, rule: Mapping[str, Any]) -> None:
        plan = self._plan_from_rule(rule, detection)
        if not plan: return
        rule_uuid = _optional_uuid(rule.get("id") or detection.rule_id)
        try:
            await self._orchestrator.run_chain(tenant_id=case.tenant_id, case_id=case.case_id, device_id=_optional_uuid(detection.entity_id) if detection.entity_type == "device" else _optional_uuid(detection.evidence.get("device_id")) if detection.evidence else None, plan=plan, issued_by=f"auto_case:{rule.get('id', detection.rule_id)}", initiated_by_rule=rule_uuid, dry_run=bool(rule.get("dry_run", False)), blast_rule_id=rule_uuid, blast_limit=max(1, int(rule.get("blast_radius_limit", 10))))
        except Exception:
            # Case creation remains durable even if response dispatch is unavailable.
            # The orchestrator records individual action failures when possible.
            return

    @staticmethod
    def _plan_from_rule(rule: Mapping[str, Any], detection: Detection) -> list[ActionPlan]:
        plan: list[ActionPlan] = []
        for entry in rule.get("auto_actions") or []:
            if not isinstance(entry, Mapping): continue
            action = str(entry.get("action") or "").strip()
            if not action: continue
            args = dict(entry.get("args") or {})
            cls = ACTION_CLASS.get(action, ActionClass.MEDIUM)
            requires = bool(entry.get("requires_approval")) or cls in (ActionClass.HIGH, ActionClass.CRITICAL)
            plan.append(ActionPlan(action=action, args=args, requires_approval=requires, rollback=entry.get("rollback")))
        return plan


def _optional_uuid(value: object) -> UUID | None:
    if value is None: return None
    try: return UUID(str(value))
    except (ValueError, AttributeError, TypeError): return None


def _enrich_case(case: Case, detection: Detection) -> Case:
    detection_ids = case.detection_ids if detection.detection_id in case.detection_ids else (*case.detection_ids, detection.detection_id)
    rule_ids = case.rule_ids if detection.rule_id in case.rule_ids else (*case.rule_ids, detection.rule_id)
    return Case(case_id=case.case_id, tenant_id=case.tenant_id, title=case.title, severity=max(case.severity, detection.severity), status=case.status, created_at=case.created_at, first_detected_at=min(case.first_detected_at, detection.observed_at), last_detected_at=max(case.last_detected_at, detection.observed_at), detection_ids=detection_ids, rule_ids=rule_ids)
