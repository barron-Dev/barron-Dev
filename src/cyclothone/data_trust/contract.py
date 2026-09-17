from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sentinel.data_trust.models import TransferDecision, TransferRequest


def transfer_wire_request(request: TransferRequest) -> dict[str, Any]:
    """Language-neutral JSON payload for endpoint agents and gateways."""
    payload = asdict(request)
    for key in ("tenant_id", "asset_id", "device_id", "actor_id"):
        value = payload.get(key)
        if value is not None:
            payload[key] = str(value)
    payload["observed_at"] = request.observed_at.isoformat()
    return payload


def transfer_wire_decision(decision: TransferDecision) -> dict[str, Any]:
    return {
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "policy_id": str(decision.policy_id) if decision.policy_id else None,
        "classification": decision.classification,
    }
