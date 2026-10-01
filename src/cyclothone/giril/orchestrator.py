from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable

from .verification import normalize_lei


@dataclass(frozen=True)
class VerificationOutcome:
    status: str
    source_key: str
    target_hash: str
    evidence: dict[str, Any]


class AuthoritativeVerificationOrchestrator:
    """Connector verifies; Trust interprets; Control admits."""
    def __init__(self, lookup: Callable[[str], dict[str, Any]], source_key: str):
        self._lookup = lookup
        self.source_key = source_key

    def verify_lei(self, lei: str) -> VerificationOutcome:
        normalized = normalize_lei(lei)
        target_hash = hashlib.sha256(normalized.encode()).hexdigest()
        payload = self._lookup(normalized)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not data:
            return VerificationOutcome("NOT_VERIFIED", self.source_key, target_hash, {"reason": "authoritative_source_no_match"})
        records = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        if len(records) != 1:
            return VerificationOutcome("MANUAL_REVIEW" if records else "ERROR", self.source_key, target_hash, {"reason": "non_unique_or_invalid_source_result", "match_count": len(records)})
        attrs = records[0].get("attributes", {})
        entity = attrs.get("entity", {})
        evidence = {"lei": attrs.get("lei"), "legal_name": (entity.get("legalName") or {}).get("name"), "entity_status": attrs.get("entityStatus"), "source_key": self.source_key}
        status = "VERIFIED" if evidence["lei"] == normalized and evidence["entity_status"] == "ACTIVE" else "NOT_VERIFIED"
        return VerificationOutcome(status, self.source_key, target_hash, evidence)


def to_check_record(outcome: VerificationOutcome, onboarding_case_id: str, verifier_version: str) -> dict[str, Any]:
    return {"onboarding_case_id": onboarding_case_id, "check_type": "COMPANY_REGISTRY", "target_hash": outcome.target_hash, "status": outcome.status, "verifier_version": verifier_version, "verification_method": "GLEIF_LEI_API", "metadata": outcome.evidence}
