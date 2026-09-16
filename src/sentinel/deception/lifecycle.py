from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sentinel.storage.supabase_client import supabase


class DeceptionLifecycle:
    """Service-role lifecycle operations for deployed deception artifacts.

    Artifact bindings are security-sensitive: changing a device or AutoCase rule
    after deployment changes where a compromise signal is attributed and what
    response workflow receives it. These operations therefore use the backend
    service client rather than tenant-side UPDATE permissions.
    """

    async def disable(self, *, tenant_id: UUID, artifact_id: UUID) -> dict[str, Any]:
        artifact = await self._get(tenant_id, artifact_id)
        if artifact is None:
            raise LookupError("deception artifact not found")
        return await supabase.update(
            "deception_artifacts",
            {"enabled": False, "updated_at": datetime.now(UTC).isoformat()},
            id=str(artifact_id),
            tenant_id=str(tenant_id),
        )

    async def enable(self, *, tenant_id: UUID, artifact_id: UUID) -> dict[str, Any]:
        artifact = await self._get(tenant_id, artifact_id)
        if artifact is None:
            raise LookupError("deception artifact not found")
        return await supabase.update(
            "deception_artifacts",
            {"enabled": True, "updated_at": datetime.now(UTC).isoformat()},
            id=str(artifact_id),
            tenant_id=str(tenant_id),
        )

    async def _get(self, tenant_id: UUID, artifact_id: UUID) -> dict[str, Any] | None:
        return await supabase.select_one(
            "deception_artifacts",
            "id,tenant_id,enabled,artifact_type,name,target,device_id,auto_case_rule_id",
            id=str(artifact_id),
            tenant_id=str(tenant_id),
        )
