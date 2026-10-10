from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid5

logger = logging.getLogger(__name__)

CHANGE_SEVERITY = {
    "NEW_ACCOUNT": 4,
    "PROFILE_MODIFICATION": 2,
    "NEW_POST": 3,
    "NEW_FOLLOWER": 2,
    "BREACH_EXPOSURE": 9,
    "STEALER_LOG_APPEARANCE": 10,
    "DARK_WEB_MENTION": 8,
    "TELEGRAM_MENTION": 7,
    "CODE_REPO_LEAK": 9,
    "INFRASTRUCTURE_CHANGE": 3,
}
RELEVANCE_SCORE = {"EXACT": 10, "FUZZY": 5}
SOURCE_RELIABILITY = {
    "hibp": 9,
    "xposedornot": 7,
    "hudson_rock": 8,
    "github_code": 8,
    "ransomwatch": 8,
    "telegram_public": 5,
    "pastebin_public": 4,
    "pastebinca": 4,
    "darkwatch": 7,
}
OBSERVED_TIME_KEYS = ("observed_at", "published_at", "published", "discovered", "last_seen", "created_at")
SAFE_KIND = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _safe_url(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parts = urlsplit(value.strip())
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            return None
        # Query strings and fragments are removed so invite tokens, tracking IDs,
        # and provider query secrets are not copied into the event ledger.
        return urlunsplit((parts.scheme, parts.netloc, parts.path[:2048], "", ""))
    except ValueError:
        return None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _observed_at(metadata: dict, collected_at: datetime) -> datetime | None:
    for key in OBSERVED_TIME_KEYS:
        parsed = _parse_time(metadata.get(key))
        if parsed:
            return parsed
    # Missing provider event time is unknown, not fresh. Never upgrade an
    # undated historical feed to "fresh" merely because we collected it now.
    return None


def _classify(source_id: str, kind: str, metadata: dict) -> str:
    source = source_id.lower()
    context = str(metadata.get("event_type") or metadata.get("change_type") or "").upper()
    if context in CHANGE_SEVERITY:
        return context
    if any(term in source for term in ("stealer", "infostealer", "credential_log")):
        return "STEALER_LOG_APPEARANCE"
    if any(term in source for term in ("hibp", "xposedornot", "hudson_rock", "breach")) or kind.lower() in {"breach", "credential"}:
        return "BREACH_EXPOSURE"
    if any(term in source for term in ("github", "code_repo", "secret_scan")):
        return "CODE_REPO_LEAK"
    if "telegram" in source:
        return "TELEGRAM_MENTION"
    return "DARK_WEB_MENTION"


def _freshness(observed_at: datetime | None, now: datetime) -> int:
    if observed_at is None:
        return 1
    age = max(timedelta(0), now - observed_at)
    if age < timedelta(hours=1):
        return 10
    if age < timedelta(hours=24):
        return 7
    if age < timedelta(hours=72):
        return 4
    return 1


def score_change(
    *,
    event_type: str,
    relevance: str,
    source_reliability: int,
    freshness: int,
) -> tuple[float, str]:
    if event_type not in CHANGE_SEVERITY:
        raise ValueError("unsupported_change_type")
    if relevance not in {"EXACT", "FUZZY", "OTHER"}:
        raise ValueError("unsupported_relevance")
    if not 0 <= source_reliability <= 10 or not 0 <= freshness <= 10:
        raise ValueError("score_component_out_of_range")
    relevance_value = RELEVANCE_SCORE.get(relevance, 2)
    score = round(
        CHANGE_SEVERITY[event_type] * 0.40
        + relevance_value * 0.25
        + source_reliability * 0.20
        + freshness * 0.15,
        2,
    )
    tier = "immediate" if score >= 7 else "scheduled" if score >= 4 else "archive"
    return score, tier


def build_change_event(finding: object, *, collected_at: datetime | None = None) -> dict:
    """Create a privacy-minimized, deterministic event from a provider finding.

    The raw matched identifier and provider payload are never copied into the event.
    Only a stable subject hash, a payload hash, and allow-listed metadata are kept.
    """
    now = collected_at or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)

    def field(name: str, default=None):
        if isinstance(finding, dict):
            return finding.get(name, default)
        return getattr(finding, name, default)

    source_id = str(field("source_id", "")).strip().lower()
    kind = str(field("kind", "")).strip().lower()
    value = str(field("matched_value", "")).strip().lower()
    metadata = field("metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    if not source_id or not kind or not value:
        raise ValueError("finding_source_kind_and_value_required")
    if not SAFE_KIND.fullmatch(source_id) or not SAFE_KIND.fullmatch(kind):
        raise ValueError("invalid_source_or_kind")

    source_url = _safe_url(field("source_url"))
    # Hash the provider material before discarding it. This digest is useful for
    # dedupe and evidence integrity without retaining the underlying payload.
    raw_payload_hash = _sha256(_canonical({
        "source_id": source_id,
        "kind": kind,
        "matched_value": value,
        "context": field("context"),
        "source_url": source_url,
        "metadata": metadata,
    }))
    subject_id = _sha256(f"{kind}:{value}")
    event_type = _classify(source_id, kind, metadata)
    relevance = str(metadata.get("relevance") or "FUZZY").upper()
    if relevance not in {"EXACT", "FUZZY"}:
        relevance = "OTHER"
    reliability = SOURCE_RELIABILITY.get(source_id, 5)
    freshness = _freshness(_observed_at(metadata, now), now)
    score, tier = score_change(
        event_type=event_type,
        relevance=relevance,
        source_reliability=reliability,
        freshness=freshness,
    )
    event_id = str(uuid5(NAMESPACE_URL, f"cyclothone:change:{raw_payload_hash}"))
    return {
        "event_id": event_id,
        "event_type": event_type,
        "subject_id": subject_id,
        "change_score": score,
        "tier": tier,
        "source_module": "darkweb",
        "source_name": source_id,
        "source_url": source_url,
        "collected_at": now.isoformat(),
        "change_details": {
            "identifier_kind": kind,
            "identifier_hash": subject_id,
            "match_mode": relevance.lower(),
            "source_reliability": reliability,
            "freshness_score": freshness,
        },
        "raw_payload_hash": raw_payload_hash,
        "screenshot_path": None,
        "rfc3161_timestamp_token": None,
    }
