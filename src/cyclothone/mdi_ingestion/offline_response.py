"""Offline MDI response planner. Plans are not device commands or destructive actions."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass

@dataclass(frozen=True)
class OfflineResponsePlan:
    disposition: str
    actions: tuple[str, ...]
    evidence_hash: str
    rule_version: str
    limitations: tuple[str, ...]

def plan_offline_response(*, disposition: str, coverage: str, corporate_container_available: bool, key_invalidation_supported: bool) -> OfflineResponsePlan:
    if disposition not in {"threat_detected","human_review_required","partial_coverage","source_unavailable","unknown"}:
        raise ValueError("unsupported disposition")
    if coverage not in {"complete","partial","unavailable"}:
        raise ValueError("unsupported coverage")
    if not isinstance(corporate_container_available,bool) or not isinstance(key_invalidation_supported,bool):
        raise ValueError("capability flags must be boolean")
    actions = ["append_encrypted_local_event","deny_new_sensitive_operations","queue_signed_receipt_for_later_sync"]
    if disposition=="threat_detected":
        if corporate_container_available: actions.append("lock_cyclothone_corporate_container")
        if key_invalidation_supported: actions.append("invalidate_cyclothone_scoped_keys")
        actions.append("require_trusted_recovery_before_reenable")
    elif disposition in {"human_review_required","partial_coverage","source_unavailable","unknown"} or coverage!="complete":
        actions.append("mark_device_posture_unverified")
    payload = {"disposition":disposition,"coverage":coverage,"actions":actions,"rule_version":"mdi-offline-response-1"}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return OfflineResponsePlan(disposition,tuple(actions),digest,"mdi-offline-response-1",
        ("This is a plan, not proof an OS action executed.","No personal data wipe, whole-device network kill, or remote command is performed.","Platform adapters must authenticate policy, protect against rollback, and report execution evidence."))
