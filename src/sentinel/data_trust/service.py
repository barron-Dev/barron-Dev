from __future__ import annotations

from typing import Any
from uuid import UUID

from sentinel.data_trust.models import TransferDecision, TransferRequest
from sentinel.storage.supabase_client import supabase


class DataTrustControlPlane:
    async def evaluate_and_record(self, request: TransferRequest) -> TransferDecision:
        asset = None
        if request.asset_id:
            asset = await supabase.select_one(
                "data_trust_assets",
                "id,tenant_id,policy_id,classification,encryption_state",
                id=request.asset_id,
                tenant_id=request.tenant_id,
            )

        policy = None
        if asset and asset.get("policy_id"):
            policy = await supabase.select_one(
                "data_trust_policies",
                "id,tenant_id,classification,allowed_destinations,allowed_device_trust,allow_removable_media,allow_bluetooth,allow_cloud_upload,encryption_required,enabled",
                id=asset["policy_id"],
                tenant_id=request.tenant_id,
            )

        if policy is None:
            decision = TransferDecision("review", ("no_active_policy",), None, asset.get("classification") if asset else None)
        else:
            reasons: list[str] = []
            classification = str(asset["classification"])
            allowed_destinations = set(policy.get("allowed_destinations") or [])
            allowed_trust = set(policy.get("allowed_device_trust") or [])

            if not policy.get("enabled"):
                decision = TransferDecision("review", ("policy_disabled",), UUID(str(policy["id"])), classification)
            else:
                if request.destination_type not in allowed_destinations:
                    reasons.append("destination_not_allowed")
                if request.destination_trust not in allowed_trust:
                    reasons.append("destination_trust_not_allowed")
                if request.destination_type == "usb" and not policy.get("allow_removable_media"):
                    reasons.append("removable_media_blocked")
                if request.destination_type == "bluetooth" and not policy.get("allow_bluetooth"):
                    reasons.append("bluetooth_blocked")
                if request.destination_type in {"cloud", "browser"} and not policy.get("allow_cloud_upload"):
                    reasons.append("cloud_upload_blocked")
                if policy.get("encryption_required") and asset.get("encryption_state") != "encrypted":
                    reasons.append("encryption_required")

                if reasons:
                    decision = TransferDecision("block", tuple(reasons), UUID(str(policy["id"])), classification)
                elif classification in {"restricted", "regulated"} and not request.content_inspected:
                    decision = TransferDecision("review", ("inspection_required",), UUID(str(policy["id"])), classification)
                else:
                    decision = TransferDecision("allow", (), UUID(str(policy["id"])), classification)

        await supabase.insert_one(
            "data_trust_transfer_events",
            {
                "tenant_id": str(request.tenant_id),
                "asset_id": str(request.asset_id) if request.asset_id else None,
                "device_id": str(request.device_id) if request.device_id else None,
                "actor_id": str(request.actor_id) if request.actor_id else None,
                "source_type": request.source_type,
                "destination_type": request.destination_type,
                "destination_ref": request.destination_ref,
                "destination_trust": request.destination_trust,
                "bytes_transferred": request.bytes_transferred,
                "content_inspected": request.content_inspected,
                "content_hash": request.content_hash,
                "decision": decision.decision,
                "reason_codes": list(decision.reason_codes),
                "observed_at": request.observed_at.isoformat(),
                "metadata": request.metadata,
            },
        )
        return decision
