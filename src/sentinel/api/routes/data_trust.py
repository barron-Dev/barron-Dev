from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from sentinel.data_trust.models import TransferRequest
from sentinel.data_trust.service import DataTrustControlPlane
from sentinel.developer.auth import DeveloperPrincipal, authenticate_request

router = APIRouter(prefix="/data-trust", tags=["data-trust"])
_control_plane = DataTrustControlPlane()


class TransferBody(BaseModel):
    asset_id: UUID | None = None
    device_id: UUID | None = None
    source_type: str = Field(min_length=1, max_length=40)
    destination_type: str = Field(min_length=1, max_length=40)
    destination_ref: str | None = Field(default=None, max_length=1000)
    destination_trust: str = Field(default="unknown", max_length=40)
    bytes_transferred: int = Field(default=0, ge=0)
    content_inspected: bool = False
    content_hash: str | None = Field(default=None, min_length=64, max_length=64)
    observed_at: datetime
    metadata: dict[str, object] = Field(default_factory=dict)


@router.post("/transfers/evaluate")
async def evaluate_transfer(body: TransferBody, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("data:transfer",))
    request = TransferRequest(
        tenant_id=UUID(principal.tenant_id),
        asset_id=body.asset_id,
        device_id=body.device_id,
        actor_id=None,
        source_type=body.source_type,
        destination_type=body.destination_type,
        destination_ref=body.destination_ref,
        destination_trust=body.destination_trust,
        bytes_transferred=body.bytes_transferred,
        content_inspected=body.content_inspected,
        content_hash=body.content_hash,
        observed_at=body.observed_at,
        metadata=body.metadata,
    )
    decision = await _control_plane.evaluate_and_record(request)
    return {
        "decision": decision.decision,
        "reason_codes": list(decision.reason_codes),
        "policy_id": str(decision.policy_id) if decision.policy_id else None,
        "classification": decision.classification,
    }
