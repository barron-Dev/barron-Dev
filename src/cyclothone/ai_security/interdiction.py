"""Safety policy for connected security-device responses.

This module does not connect to drones/robots and cannot issue MAVSDK commands. It creates
a review/approval decision for low-risk safety actions. Pursuit, interception, weaponized,
coercive, or target-following commands are explicitly denied.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
import hashlib
import json
import uuid

Action = Literal["alert_operator", "hold_position", "return_to_home", "safe_stop",
                 "intercept_target", "pursue_target", "arm", "takeoff", "goto_location"]


@dataclass(frozen=True, slots=True)
class ResponseRequest:
    tenant_id: str
    device_id: str
    action: Action
    evidence_ids: tuple[str, ...]
    policy_version: str
    requester_id: str
    requested_at: datetime


_DENIED = {"intercept_target", "pursue_target", "arm", "takeoff", "goto_location"}
_ALLOWED_REVIEW = {"alert_operator", "hold_position", "return_to_home", "safe_stop"}


def evaluate_response_request(request: ResponseRequest, *,
                              verified_evidence_ids: frozenset[str],
                              device_tenant_id: str | None,
                              device_allowlisted: bool,
                              kill_switch_active: bool,
                              human_approval_id: str | None = None) -> dict:
    if not request.tenant_id or not request.device_id or not request.requester_id:
        raise ValueError("request_identity_required")
    if request.requested_at.tzinfo is None or request.requested_at.utcoffset() is None:
        raise ValueError("requested_at_must_be_timezone_aware")
    reasons = []
    if request.action in _DENIED:
        reasons.append("physical_interception_or_unbounded_motion_not_permitted")
    elif request.action not in _ALLOWED_REVIEW:
        reasons.append("action_not_allowlisted")
    if device_tenant_id != request.tenant_id:
        reasons.append("device_tenant_mismatch")
    if not device_allowlisted:
        reasons.append("device_not_allowlisted")
    if kill_switch_active:
        reasons.append("ai_security_kill_switch_active")
    if not request.evidence_ids or not set(request.evidence_ids).issubset(verified_evidence_ids):
        reasons.append("verified_evidence_required")
    approval_required = request.action in {"hold_position", "return_to_home", "safe_stop"}
    if approval_required and not human_approval_id:
        reasons.append("explicit_human_approval_required")
    payload = {"schema":"cyclothone.ai-security-response-decision.v1",
               "decision_id":str(uuid.uuid4()),"tenant_id":request.tenant_id,
               "device_id":request.device_id,"action":request.action,
               "evidence_ids":list(request.evidence_ids),"policy_version":request.policy_version,
               "requester_id":request.requester_id,
               "requested_at":request.requested_at.astimezone(timezone.utc).isoformat(),
               "human_approval_id":human_approval_id,"approval_required":approval_required,
               "decision":"deny" if reasons else "approval_recorded_not_dispatched",
               "reasons":reasons,"dispatch_permitted":False}
    payload["decision_sha256"] = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return payload
