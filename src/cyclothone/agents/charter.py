from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_ALLOWED_ACTIONS = frozenset({
    "scan_now", "collect_forensics", "kill_process", "quarantine_file",
    "block_hash", "block_ip", "restore_file", "isolate_host",
    "release_host", "force_logout", "disable_account",
})
_MAX_LIST = 128


@dataclass(frozen=True, slots=True)
class Charter:
    allowed_actions: frozenset[str]
    forbidden_targets: frozenset[str]
    max_blast_radius: int
    max_actions_per_hour: int
    requires_approval_above: float
    min_confidence: float
    business_hours_only: bool
    business_hours_start: int
    business_hours_end: int
    rollback_required: bool
    max_risk_per_action: float

    @classmethod
    def from_json(cls, value: dict[str, Any] | None) -> "Charter":
        raw = value if isinstance(value, dict) else {}

        actions = raw.get("allowed_actions")
        if actions is None:
            actions = ["kill_process", "quarantine_file", "block_hash", "block_ip", "scan_now"]
        if not isinstance(actions, list) or not actions or len(actions) > _MAX_LIST:
            raise ValueError("charter.allowed_actions must be a bounded non-empty list")
        if any(not isinstance(a, str) or a not in _ALLOWED_ACTIONS for a in actions):
            raise ValueError("charter contains an unsupported action")

        forbidden = raw.get("forbidden_targets") or []
        if not isinstance(forbidden, list) or len(forbidden) > _MAX_LIST:
            raise ValueError("charter.forbidden_targets must be bounded")
        if any(not isinstance(x, str) or not x.strip() or len(x) > 256 for x in forbidden):
            raise ValueError("invalid forbidden target")

        max_blast = _int(raw, "max_blast_radius", 5, 0, 1000)
        max_rate = _int(raw, "max_actions_per_hour", 20, 1, 100000)
        approval = _float(raw, "requires_approval_above", 0.85)
        minimum = _float(raw, "min_confidence", 0.75)
        risk = _float(raw, "max_risk_per_action", 0.5)

        if minimum < 0 or minimum > 1 or approval < 0 or approval > 1 or risk < 0 or risk > 1:
            raise ValueError("charter thresholds must be in [0,1]")

        start = _int(raw, "business_hours_start", 8, 0, 23)
        end = _int(raw, "business_hours_end", 20, 1, 24)
        if start >= end:
            raise ValueError("business hours must be a non-empty interval")

        return cls(
            allowed_actions=frozenset(actions),
            forbidden_targets=frozenset(forbidden),
            max_blast_radius=max_blast,
            max_actions_per_hour=max_rate,
            requires_approval_above=approval,
            min_confidence=minimum,
            business_hours_only=bool(raw.get("business_hours_only", False)),
            business_hours_start=start,
            business_hours_end=end,
            rollback_required=bool(raw.get("rollback_required", True)),
            max_risk_per_action=risk,
        )


def _int(raw: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if not low <= value <= high:
        raise ValueError(f"{key} outside allowed range")
    return value


def _float(raw: dict[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be numeric")
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be numeric") from exc
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{key} must be finite")
    return value


@dataclass(frozen=True, slots=True)
class GateResult:
    name: str
    passed: bool
    value: Any
    limit: Any
    reason: str


class CharterGate:
    """Deterministic safety kernel. A single failed hard gate denies execution."""

    def evaluate(
        self,
        charter: Charter,
        action: str,
        target_device_label: str | None,
        confidence: float,
        blast_radius: int,
        actions_last_hour: int,
        risk_score: float,
        now: datetime | None = None,
    ) -> tuple[bool, list[GateResult]]:
        now = now or datetime.now(timezone.utc)
        gates: list[GateResult] = []

        checks = (
            ("allowed_action", action in charter.allowed_actions, action, sorted(charter.allowed_actions)),
            ("forbidden_target",
             not (target_device_label and target_device_label in charter.forbidden_targets),
             target_device_label or "-", sorted(charter.forbidden_targets)),
            ("blast_radius",
             0 <= blast_radius <= charter.max_blast_radius, blast_radius, charter.max_blast_radius),
            ("rate_limit",
             0 <= actions_last_hour < charter.max_actions_per_hour,
             actions_last_hour, charter.max_actions_per_hour),
        )
        for name, ok, value, limit in checks:
            reason = f"{name}: value={value!r}, limit={limit!r}"
            gates.append(GateResult(name, ok, value, limit, reason))
            if not ok:
                return False, gates

        if charter.business_hours_only:
            hour = now.hour
            ok = charter.business_hours_start <= hour < charter.business_hours_end
            gates.append(GateResult(
                "business_hours", ok, hour,
                f"{charter.business_hours_start}-{charter.business_hours_end}",
                f"UTC hour {hour}",
            ))
            if not ok:
                return False, gates
        else:
            gates.append(GateResult("business_hours", True, "*", "*", "no time restriction"))

        if not 0 <= confidence <= 1:
            gates.append(GateResult("confidence", False, confidence, charter.min_confidence, "confidence outside [0,1]"))
            return False, gates
        ok = confidence >= charter.min_confidence
        gates.append(GateResult("confidence", ok, round(confidence, 6), charter.min_confidence, "confidence floor"))
        if not ok:
            return False, gates

        if not 0 <= risk_score <= 1:
            gates.append(GateResult("risk_cap", False, risk_score, charter.max_risk_per_action, "risk outside [0,1]"))
            return False, gates
        ok = risk_score <= charter.max_risk_per_action
        gates.append(GateResult("risk_cap", ok, round(risk_score, 6), charter.max_risk_per_action, "risk cap"))
        if not ok:
            return False, gates

        if charter.rollback_required and action in {"kill_process", "quarantine_file", "block_hash", "block_ip", "disable_account"}:
            gates.append(GateResult("rollback_contract", True, True, True, "rollback contract required"))
        else:
            gates.append(GateResult("rollback_contract", True, False, charter.rollback_required, "no rollback requirement for this action"))

        return True, gates
