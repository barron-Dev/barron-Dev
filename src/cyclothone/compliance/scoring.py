from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

CATEGORY_WEIGHTS = {
    "access": 1.0,
    "encryption": 1.0,
    "endpoint": 0.9,
    "monitoring": 0.9,
    "response": 0.85,
    "availability": 0.8,
    "network": 0.8,
    "governance": 0.6,
}
STATUS_SCORES = {"passing": 1.0, "partial": 0.5, "failing": 0.0, "unknown": 0.25, "not_applicable": None}

@dataclass(frozen=True, slots=True)
class ScoreResult:
    score: float
    passing: int
    partial: int
    failing: int
    unknown: int
    total: int
    weighted_total: float

class ComplianceScorer:
    """Internal readiness posture metric; never an auditor opinion or certification."""

    def score(self, controls: list[dict[str, Any]], statuses: dict[str, dict[str, Any]], exceptions: dict[str, dict[str, Any]] | None = None, now: datetime | None = None) -> ScoreResult:
        exceptions = exceptions or {}
        current = now or datetime.now(UTC)
        counts = {"passing": 0, "partial": 0, "failing": 0, "unknown": 0}
        weighted_sum = weighted_total = 0.0
        total = 0
        for control in controls:
            control_id = str(control["id"])
            st = statuses.get(control_id, {})
            status = str(st.get("status", "unknown"))
            base = STATUS_SCORES.get(status)
            if base is None:
                continue
            counts[status if status in counts else "unknown"] += 1
            if control_id in exceptions and exceptions[control_id].get("status") in {"remediating", "accepted"}:
                base = max(base, 0.7)
            last = st.get("last_evaluated")
            if last:
                try:
                    observed = last if isinstance(last, datetime) else datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                    if observed.tzinfo is not None:
                        age_days = max(0, (current - observed).days)
                        if age_days > 30:
                            base *= max(0.5, 1.0 - (age_days - 30) * 0.005)
                except (TypeError, ValueError):
                    pass
            weight = float(CATEGORY_WEIGHTS.get(str(control.get("category", "governance")), 0.7))
            weighted_sum += base * weight
            weighted_total += weight
            total += 1
        return ScoreResult(round(weighted_sum / weighted_total, 4) if weighted_total else 0.0, counts["passing"], counts["partial"], counts["failing"], counts["unknown"], total, round(weighted_total, 2))
