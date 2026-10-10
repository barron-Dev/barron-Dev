from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Deterministic, explainable triage weights. These are starting policy values,
# not claims of statistically validated predictive accuracy.
SEVERITY_BASE = {"medium": 0.42, "high": 0.60, "critical": 0.72}
SOURCE_RELIABILITY = {
    "hibp": 0.16,
    "github_code": 0.12,
    "ransomwatch": 0.10,
    "telegram_public": 0.06,
    "pastebin_public": 0.04,
}
KIND_IMPACT = {
    "api_key_hash": 0.18,
    "email": 0.12,
    "domain": 0.12,
    "ip": 0.10,
    "employee_id": 0.10,
    "customer_id": 0.10,
    "phone": 0.08,
    "wallet": 0.08,
    "executive_name": 0.08,
    "company_name": 0.06,
}
ALERT_THRESHOLD = 0.72


def _freshness_bonus(metadata: dict[str, Any], now: datetime) -> tuple[float, str]:
    raw = metadata.get("published") or metadata.get("discovered") or metadata.get("observed_at")
    if not isinstance(raw, str) or not raw.strip():
        return 0.0, "publication_time_unknown"
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        age_days = max(0.0, (now - stamp.astimezone(UTC)).total_seconds() / 86400)
    except (ValueError, OverflowError):
        return 0.0, "publication_time_invalid"
    if age_days <= 1:
        return 0.08, "published_within_24h"
    if age_days <= 7:
        return 0.05, "published_within_7d"
    if age_days <= 30:
        return 0.02, "published_within_30d"
    return 0.0, "older_than_30d"


def assess_finding(
    finding: dict[str, Any],
    *,
    target_matched: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a bounded explainable risk score for a normalized DW finding.

    The score is a deterministic prioritization signal, not a probability of
    compromise. Exact watchlist matching is a prerequisite for alert eligibility.
    """
    now = now or datetime.now(UTC)
    severity = str(finding.get("severity") or "medium").strip().lower()
    source_id = str(finding.get("source_id") or "").strip().lower()
    kind = str(finding.get("kind") or "").strip().lower()
    metadata = finding.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    score = SEVERITY_BASE.get(severity, SEVERITY_BASE["medium"])
    factors: list[dict[str, Any]] = [
        {"factor": "source_severity", "value": severity, "contribution": SEVERITY_BASE.get(severity, SEVERITY_BASE["medium"])}
    ]
    source_bonus = SOURCE_RELIABILITY.get(source_id, 0.02)
    score += source_bonus
    factors.append({"factor": "source_reliability_prior", "value": source_id or "unknown", "contribution": source_bonus})
    impact_bonus = KIND_IMPACT.get(kind, 0.04)
    score += impact_bonus
    factors.append({"factor": "identifier_impact_prior", "value": kind or "unknown", "contribution": impact_bonus})

    freshness_bonus, freshness_reason = _freshness_bonus(metadata, now)
    score += freshness_bonus
    factors.append({"factor": "freshness", "value": freshness_reason, "contribution": freshness_bonus})

    if target_matched:
        score += 0.12
        factors.append({"factor": "exact_authorized_watchlist_match", "value": True, "contribution": 0.12})
    else:
        factors.append({"factor": "exact_authorized_watchlist_match", "value": False, "contribution": 0.0})

    score = round(min(0.99, max(0.0, score)), 4)
    return {
        "risk_score": score,
        "risk_factors": factors,
        "alert_eligible": bool(target_matched and score >= ALERT_THRESHOLD),
        "alert_threshold": ALERT_THRESHOLD,
        "score_semantics": "deterministic prioritization score; not a probability of compromise",
    }
