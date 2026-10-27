"""Deterministic, fail-closed evaluator for Cyclothone evidence lifecycle conflicts.

Evaluates supplied, versioned obligation records. It is not a legal precedence
engine and cannot authorize data deletion by itself.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Literal, Mapping, Sequence

RequestedAction = Literal["delete", "pseudonymize", "restrict_access", "retain"]
DecisionState = Literal["no_conflict", "conflict_detected", "applicability_unknown"]


@dataclass(frozen=True)
class EvidenceContext:
    tenant_id: str
    evidence_id: str
    evidence_sha256: str
    jurisdiction: str | None
    evidence_class: str | None
    collected_at: datetime
    attributes: Mapping[str, str | int | bool | None]


@dataclass(frozen=True)
class RetentionObligation:
    obligation_key: str
    source_citation: str
    source_version: str
    jurisdiction: str
    evidence_class: str
    effective_from: datetime
    effective_until: datetime | None
    reviewed: bool
    applicability: Mapping[str, str | int | bool]
    required_actions: tuple[str, ...]
    source_digest: str | None = None
    freshness_deadline: datetime | None = None


@dataclass(frozen=True)
class Conflict:
    obligation_key: str
    source_citation: str
    source_version: str
    required_actions: tuple[str, ...]
    requested_action: str
    reason_code: str


@dataclass(frozen=True)
class Evaluation:
    state: DecisionState
    requested_action: str
    matched_obligations: tuple[str, ...]
    unknown_obligations: tuple[str, ...]
    conflicts: tuple[Conflict, ...]
    reason_codes: tuple[str, ...]
    evaluated_at: datetime
    evaluator_version: str
    snapshot_sha256: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evaluated_at"] = self.evaluated_at.isoformat()
        result["conflicts"] = [asdict(item) for item in self.conflicts]
        return result


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive_datetime_forbidden")
    return value.astimezone(timezone.utc)


def _applies(item: RetentionObligation, evidence: EvidenceContext, now: datetime) -> tuple[bool | None, str | None]:
    if evidence.jurisdiction is None or evidence.evidence_class is None:
        return None, "evidence_context_incomplete"
    if evidence.jurisdiction != item.jurisdiction or evidence.evidence_class != item.evidence_class:
        return False, None
    if now < _utc(item.effective_from) or (item.effective_until is not None and now >= _utc(item.effective_until)):
        return False, None
    if not item.reviewed:
        return None, "obligation_not_legally_reviewed"
    if item.source_digest is None or len(item.source_digest) != 64 or any(c not in "0123456789abcdef" for c in item.source_digest):
        return None, "obligation_source_digest_missing_or_invalid"
    if item.freshness_deadline is not None and now > _utc(item.freshness_deadline):
        return None, "obligation_source_stale"
    for key, expected in item.applicability.items():
        if key not in evidence.attributes or evidence.attributes[key] is None:
            return None, "applicability_attribute_unknown"
        if evidence.attributes[key] != expected:
            return False, None
    if not item.required_actions:
        return None, "obligation_actions_missing"
    return True, None


def evaluate_lifecycle_request(
    evidence: EvidenceContext,
    obligations: Sequence[RetentionObligation],
    requested_action: RequestedAction,
    *,
    now: datetime,
    evaluator_version: str = "cyclothone-conflict-evaluator/1",
) -> Evaluation:
    """Evaluate obligations; never executes deletion or chooses legal precedence.

    Unknown context, stale/unreviewed sources, and malformed rules block the
    decision. Callers must separately verify evidence bytes, requester authority,
    signatures, legal holds, and the lifecycle executor's result.
    """
    at = _utc(now)
    _utc(evidence.collected_at)
    if len(evidence.evidence_sha256) != 64 or any(c not in "0123456789abcdef" for c in evidence.evidence_sha256):
        raise ValueError("evidence_digest_must_be_lowercase_sha256")
    if not evidence.tenant_id or not evidence.evidence_id:
        raise ValueError("tenant_and_evidence_identity_required")
    if requested_action not in {"delete", "pseudonymize", "restrict_access", "retain"}:
        raise ValueError("unsupported_lifecycle_action")

    matched: list[str] = []
    unknown: list[str] = []
    conflicts: list[Conflict] = []
    reasons: set[str] = set()
    for item in sorted(obligations, key=lambda x: (x.obligation_key, x.source_version)):
        applies, reason = _applies(item, evidence, at)
        if reason:
            unknown.append(item.obligation_key)
            reasons.add(reason)
        elif applies is None:
            unknown.append(item.obligation_key)
            reasons.add("applicability_unknown")
        elif applies:
            matched.append(item.obligation_key)
            allowed = set(item.required_actions)
            if requested_action not in allowed:
                conflicts.append(Conflict(
                    item.obligation_key, item.source_citation, item.source_version,
                    tuple(sorted(allowed)), requested_action,
                    "requested_action_not_permitted_by_obligation",
                ))

    if not obligations:
        state: DecisionState = "applicability_unknown"
        reasons.add("no_applicable_obligation_data")
    elif unknown:
        state = "applicability_unknown"
    elif conflicts:
        state = "conflict_detected"
    elif not matched:
        state = "applicability_unknown"
        reasons.add("no_matching_reviewed_obligation")
    else:
        state = "no_conflict"

    snapshot = {
        "tenant_id": evidence.tenant_id, "evidence_id": evidence.evidence_id,
        "evidence_sha256": evidence.evidence_sha256, "jurisdiction": evidence.jurisdiction,
        "evidence_class": evidence.evidence_class, "requested_action": requested_action,
        "matched_obligations": sorted(matched), "unknown_obligations": sorted(unknown),
        "conflicts": [asdict(item) for item in conflicts], "reason_codes": sorted(reasons),
        "evaluated_at": at.isoformat(), "evaluator_version": evaluator_version,
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return Evaluation(
        state, requested_action, tuple(sorted(matched)), tuple(sorted(unknown)),
        tuple(conflicts), tuple(sorted(reasons)), at, evaluator_version,
        sha256(canonical.encode("utf-8")).hexdigest(),
    )
