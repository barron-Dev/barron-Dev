from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class Observation:
    control_id: str
    first_seen: datetime | None
    last_seen: datetime | None
    evidence_count: int
    fresh: bool
    coverage: float
    operating_effectiveness: str


class AssuranceEngine:
    """Builds a deterministic control/evidence view for readiness and audit work.

    This is a measurement layer. It does not issue an auditor opinion.
    """

    @staticmethod
    def observations(
        controls: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        collection_results: list[dict[str, Any]],
        period_start: datetime,
        period_end: datetime,
        now: datetime | None = None,
    ) -> list[Observation]:
        current = now or datetime.now(UTC)
        evidence_by_control: dict[str, list[dict[str, Any]]] = {}
        results_by_control: dict[str, list[dict[str, Any]]] = {}
        for item in evidence:
            evidence_by_control.setdefault(str(item.get("control_id")), []).append(item)
        for item in collection_results:
            results_by_control.setdefault(str(item.get("control_id")), []).append(item)

        output: list[Observation] = []
        for control in controls:
            cid = str(control.get("id"))
            items = evidence_by_control.get(cid, [])
            results = results_by_control.get(cid, [])
            timestamps: list[datetime] = []
            for item in items:
                parsed = AssuranceEngine._timestamp(item.get("collected_at"))
                if parsed and period_start <= parsed <= period_end:
                    timestamps.append(parsed)
            first_seen = min(timestamps) if timestamps else None
            last_seen = max(timestamps) if timestamps else None

            expected = {str(x) for x in (control.get("evidence_sources") or [])}
            observed_sources = {
                str(x.get("source_ref"))
                for x in results
                if str(x.get("status")) in {"collected", "empty"}
            }
            coverage = 1.0 if not expected else len(expected & observed_sources) / len(expected)
            fresh = bool(items) and all(not AssuranceEngine._is_stale(x.get("valid_until"), current) for x in items[-min(len(items), 100):])

            successful = sum(str(x.get("status")) == "collected" and not bool(x.get("stale")) for x in results)
            failed = sum(str(x.get("status")) == "failed" for x in results)
            if not items or coverage == 0 or failed > 0 and successful == 0:
                effectiveness = "insufficient_evidence"
            elif coverage < 1.0 or not fresh:
                effectiveness = "partial_coverage"
            else:
                effectiveness = "observed"

            output.append(Observation(cid, first_seen, last_seen, len(items), fresh, round(coverage, 4), effectiveness))
        return output

    @staticmethod
    def period_mode(engagement_type: str, period_start: datetime, period_end: datetime, now: datetime | None = None) -> str:
        """Return the evidence semantics for an engagement period.

        Type I evaluates the specified point-in-time state. Type II requires
        operating evidence across the stated period; an open future period is
        reported as incomplete rather than treated as successful.
        """
        if engagement_type not in {"type1", "type2"}:
            raise ValueError("engagement_type must be type1 or type2")
        current = now or datetime.now(UTC)
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValueError("engagement period must be timezone-aware and ordered")
        if engagement_type == "type1":
            return "point_in_time"
        return "operating_period_complete" if period_end <= current else "operating_period_open"

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value if value.tzinfo else None
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_stale(value: Any, now: datetime) -> bool:
        parsed = AssuranceEngine._timestamp(value)
        return parsed is None or parsed <= now
