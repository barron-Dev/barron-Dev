from __future__ import annotations

from typing import Any
from uuid import UUID

from sentinel.storage.supabase_client import supabase


class DataTrustEnforcementService:
    """Persist the result of an authorized endpoint enforcement action.

    This service never claims that an OS-level block occurred by itself. The
    endpoint adapter must perform the action and only then report the result.
    """

    async def acknowledge(
        self,
        *,
        tenant_id: UUID,
        event_id: UUID,
        enforced: bool,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = await supabase.rpc(
            "report_data_trust_enforcement",
            {
                "p_tenant_id": str(tenant_id),
                "p_event_id": str(event_id),
                "p_status": "enforced" if enforced else "failed",
                "p_metadata": metadata or {},
            },
        )
        if not result:
            raise LookupError("transfer event not found or not enforceable")
        if isinstance(result, list):
            return result[0]
        return result
