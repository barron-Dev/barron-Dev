from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

CRITICALITY_WEIGHT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
REQUIRED_BY_DATA = {"pii": {"gdpr", "soc2"}, "phi": {"hipaa", "soc2"}, "pci": {"pci", "soc2"}, "secrets": {"soc2"}, "public": set()}

@dataclass(frozen=True, slots=True)
class VendorScore:
    score: float
    band: str
    reasons: list[str]

class VendorRiskScorer:
    """Vendor posture heuristic. It is a risk signal, not a compliance determination."""
    def score(self, vendor: dict[str, Any], now: datetime | None = None) -> VendorScore:
        current = now or datetime.now(UTC)
        weight = CRITICALITY_WEIGHT.get(str(vendor.get("criticality", "medium")), 0.5)
        score = 1.0
        reasons: list[str] = []
        required: set[str] = set()
        for data_class in set(vendor.get("data_access") or []):
            required |= REQUIRED_BY_DATA.get(str(data_class), set())
        missing = sorted(r for r in required if not bool(vendor.get(r)))
        if missing:
            score -= 0.3 * weight
            reasons.append(f"missing compliance evidence: {', '.join(missing)}")
        next_review = vendor.get("next_review_at")
        if next_review:
            try:
                review = next_review if isinstance(next_review, datetime) else datetime.fromisoformat(str(next_review).replace("Z", "+00:00"))
                if review.tzinfo is not None and review < current:
                    days = (current - review).days
                    score -= min(0.3, days / 365 * 0.3)
                    reasons.append(f"review overdue by {days} days")
            except (TypeError, ValueError):
                reasons.append("review date could not be parsed")
        if not (vendor.get("report_urls") or []):
            score -= 0.15 * weight
            reasons.append("no compliance report on file")
        score = max(0.0, min(1.0, score))
        band = "low" if score >= 0.75 else "medium" if score >= 0.45 else "high"
        return VendorScore(round(score, 3), band, reasons)
